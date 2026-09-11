/**
 * Bootstrap TideCloak for the Hospital Emergency Platform.
 *
 * Ordering is load-bearing and must not be rearranged:
 *
 *   1.  clean state (stale H2 files cause "Could not open file")
 *   2.  start container
 *   3.  wait for readiness
 *   4.  create realm from template
 *   5.  setUpTideRealm            <- Tide licensing. Genuinely calls out; takes ~7-15s.
 *   6.  toggle-iga                <- MUST come after licensing (jwk is only injected with IGA on)
 *   7.  drain change requests
 *   8.  create app users + grant hospital roles, draining and READING BACK after each
 *   9.  enrollment links for every user
 *   10. point the Tide IdP at this realm's console + sign-idp-settings
 *   11. grant tide-realm-admin  <- LAST. This flips firstAdmin -> multiAdmin, after which no
 *                                  change request can be approved from a script at all
 *                                  (409 MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE). Every governed
 *                                  write must already be committed by this point.
 *   12. export adapter JSON and assert the Tide extensions are present
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import {
  PROJECT_ROOT,
  loadEnv,
  sleep,
  adminFetch,
  adminFetchOk,
  drainChangeRequests,
  getClientUuid,
  findUser,
  listRealmRoles,
  getEnrollmentLink,
} from "./lib/tidecloak.mjs";

const CONTAINER = "tidecloak-hospital";
const IMAGE = "tideorg/tidecloak-dev:latest";

/**
 * The five demo users from the requirements, plus the realm roles each holds.
 *
 * Read the `tagRoles` column as "what this user can DECRYPT". The Forseti contract derives the
 * required realm role from the ciphertext's tag, so holding `careteam-patient-1` is exactly what
 * makes patient 1's reports readable — and the absence of it is what makes them unreadable, at
 * the ORK network rather than in our application code.
 */
const USERS = [
  {
    username: "coordinator",
    firstName: "Casey",
    lastName: "Coordinator",
    email: "coordinator@hospital.example",
    appRoles: ["coordinator"],
    encryptRole: true,
    tagRoles: ["response-team-infection-control"],
    note: "Creates the alert. Can encrypt (clinical-staff) and read back her own alert.",
  },
  {
    username: "nurse-a",
    firstName: "Nadia",
    lastName: "Nurse",
    email: "nurse-a@hospital.example",
    appRoles: ["nurse", "emergency-responder"],
    encryptRole: true,
    tagRoles: ["response-team-infection-control", "careteam-patient-1"],
    note: "Authorised responder AND on patient 1's care team. Files the incident report.",
  },
  {
    username: "doctor-a",
    firstName: "Dana",
    lastName: "Doctor",
    email: "doctor-a@hospital.example",
    appRoles: ["doctor", "emergency-responder"],
    encryptRole: true,
    tagRoles: ["response-team-infection-control", "careteam-patient-1"],
    note: "On patient 1's care team. Can read the protected report.",
  },
  {
    username: "doctor-b",
    firstName: "Ben",
    lastName: "Doctor",
    email: "doctor-b@hospital.example",
    appRoles: ["doctor", "emergency-responder"],
    encryptRole: true,
    tagRoles: [],
    note: "Doctor from another ward. Valid account, valid clinical roles, NO tag roles. The ORK network refuses to decrypt for him.",
  },
  {
    username: "hospital-admin",
    firstName: "Alex",
    lastName: "Admin",
    email: "hospital-admin@hospital.example",
    appRoles: ["hospital-admin"],
    encryptRole: false,
    tagRoles: [],
    note: "Application/database administrator. Holds no clinical-staff and no tag roles, so cannot encrypt or decrypt no matter what he writes into SQLite.",
  },
];

function docker(args, { ignoreError = false } = {}) {
  try {
    return execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    if (ignoreError) return "";
    throw err;
  }
}

function step(n, msg) {
  console.log(`\n[${n}] ${msg}`);
}

async function main() {
  const cfg = loadEnv();
  console.log("TideCloak bootstrap — Hospital Emergency Platform");
  console.log(`  TideCloak : ${cfg.tidecloakUrl}`);
  console.log(`  App       : ${cfg.appUrl}`);
  console.log(`  Realm     : ${cfg.realm}`);
  console.log(`  Client    : ${cfg.clientName}`);

  const dataDir = resolve(PROJECT_ROOT, "tidecloak", "h2");
  const wipe = process.argv.includes("--wipe");

  /**
   * Is a healthy TideCloak already serving our realm?
   *
   * This script must be safely re-runnable. Recreating the container and re-POSTing the realm on a
   * re-run produced a confusing 500 (the realm already existed, and realm-import reports almost
   * nothing usefully). Worse, it briefly tore down a working instance. So probe first.
   */
  async function realmIsServed() {
    try {
      const res = await fetch(`${cfg.tidecloakUrl}/realms/${cfg.realm}/.well-known/openid-configuration`);
      if (!res.ok) return false;
      const probe = await adminFetch(cfg, `/admin/realms/${cfg.realm}`);
      return probe.ok;
    } catch {
      return false;
    }
  }

  const alreadyServed = !wipe && (await realmIsServed());

  if (alreadyServed) {
    step(1, `Realm "${cfg.realm}" is already up — reusing it`);
    console.log("  Skipping container recreation, realm import, licensing and IGA toggle.");
    console.log("  Pass --wipe to tear everything down and start clean.");
  } else {
    /* ---------------- 1-2. clean state and start the container ---------------- */
    step(1, "Cleaning previous container state");
    docker(["stop", CONTAINER], { ignoreError: true });
    docker(["rm", CONTAINER], { ignoreError: true });

    if (wipe && existsSync(dataDir)) {
      console.log("  --wipe given: removing the H2 database directory");
      rmSync(dataDir, { recursive: true, force: true });
    }
    mkdirSync(dataDir, { recursive: true });

    step(2, `Starting ${IMAGE}`);
    // Mount a DEDICATED subdirectory, never the project root: the container writes H2 files as
    // UID 1000, and mounting the root gives AccessDeniedException plus DB files in the source tree.
    // Do NOT append `start-dev` and do NOT set SYSTEM_HOME_ORK / USER_HOME_ORK / THRESHOLD_* /
    // PAYER_PUBLIC — the image ships working ORK and threshold defaults, and overriding them risks
    // a broken threshold configuration.
    docker([
      "run", "-d",
      "--name", CONTAINER,
      "-v", `${dataDir}:/opt/keycloak/data/h2`,
      "-p", "8080:8080",
      "-e", `KC_BOOTSTRAP_ADMIN_USERNAME=${cfg.adminUser}`,
      "-e", `KC_BOOTSTRAP_ADMIN_PASSWORD=${cfg.adminPassword}`,
      IMAGE,
    ]);

    /* ---------------- 3. wait for readiness ---------------- */
    step(3, "Waiting for TideCloak to accept admin tokens");
    let ready = false;
    for (let i = 1; i <= 60; i++) {
      try {
        const res = await fetch(`${cfg.tidecloakUrl}/realms/master/.well-known/openid-configuration`);
        if (res.ok) {
          // The HTTP port answering is not the admin API being usable.
          const { getAdminToken } = await import("./lib/tidecloak.mjs");
          await getAdminToken(cfg);
          // ...and an admin token working is still not the realm store being queryable. Confirm
          // we can list realms before proceeding, or the realm-existence check below races.
          const list = await adminFetch(cfg, "/admin/realms");
          if (list.ok) {
            ready = true;
            console.log(`  ready after ~${i * 3}s`);
            break;
          }
        }
      } catch {
        /* still starting */
      }
      if (i % 5 === 0) console.log(`  ...waiting (${i * 3}s)`);
      await sleep(3000);
    }
    if (!ready) {
      console.error("TideCloak did not become ready. Container logs:");
      console.error(docker(["logs", "--tail", "60", CONTAINER], { ignoreError: true }));
      process.exit(1);
    }

    /* ---------------- 4. create the realm ---------------- */
    step(4, `Creating realm "${cfg.realm}" from template`);
    const existing = await adminFetch(cfg, `/admin/realms/${cfg.realm}`);
    if (existing.ok) {
      console.log("  realm already exists — skipping creation");
    } else {
      const template = readFileSync(resolve(PROJECT_ROOT, "tidecloak", "realm.json.template"), "utf8");
      const realmJson = template
        .replaceAll("REALM_NAME", cfg.realm)
        .replaceAll("CLIENT_NAME", cfg.clientName)
        .replaceAll("CLIENT_APP_URL", cfg.appUrl);

      const parsedTemplate = JSON.parse(realmJson);

      // Guard the failure we actually hit: KEYCLOAK_ROLE.DESCRIPTION is VARCHAR(255), and
      // exceeding it makes realm-import fail with a bare 500 that names nothing.
      for (const r of parsedTemplate.roles?.realm ?? []) {
        if ((r.description || "").length > 255) {
          console.error(
            `  ERROR: role "${r.name}" description is ${r.description.length} chars; ` +
              "the DESCRIPTION column is VARCHAR(255) and import will fail with an opaque 500."
          );
          process.exit(1);
        }
      }

      const create = await adminFetch(cfg, "/admin/realms", { method: "POST", json: parsedTemplate });
      if (!create.ok) {
        console.error(`  ERROR: realm import failed (${create.status}): ${create.text?.slice(0, 300)}`);
        console.error("  Realm import validates almost nothing up front. Read the real cause with:");
        console.error(`    docker logs ${CONTAINER} 2>&1 | Select-String "Caused by"`);
        process.exit(1);
      }
      console.log("  created");
    }
  }



  /* ---------------- 5-6. licensing and IGA (first run only) ---------------- */
  if (alreadyServed) {
    step(5, "Licensing and IGA — already done, verifying only");
    const check = await adminFetchOk(cfg, `/admin/realms/${cfg.realm}`);
    console.log(`  isIGAEnabled = ${check.body?.attributes?.isIGAEnabled}`);
    console.log(`  iga.attestor = ${check.body?.attributes?.["iga.attestor"]}`);
    if (check.body?.attributes?.isIGAEnabled !== "true") {
      console.error("  ERROR: IGA is not enabled on an existing realm. Re-run with --wipe.");
      process.exit(1);
    }
  } else {
    step(5, "setUpTideRealm (Tide licensing — reaches Tide's licensing service, ~7-15s)");
    const t0 = Date.now();
    const license = await adminFetch(cfg, `/admin/realms/${cfg.realm}/vendorResources/setUpTideRealm`, {
      method: "POST",
      form: { email: cfg.licenseEmail, isRagnarokEnabled: "true" },
    });
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`  status ${license.status} in ${elapsed}s`);
    if (!license.ok) {
      console.error(`  setUpTideRealm FAILED: ${license.text?.slice(0, 600)}`);
      if (Number(elapsed) < 2) {
        // Timing alone is diagnostic here: a real licensing call takes 7-15s.
        console.error("  Completed in under 2s, so no outbound licensing call was made.");
        console.error("  Check outbound network access to the Tide ORK network.");
      }
      console.error("  Do NOT retry in place: a failed run leaves tide-vendor-key and the tide IdP");
      console.error("  behind, and retrying then reports REALM_SETUP_FAILED, which is misleading");
      console.error("  about its own cause. Re-run with --wipe for a genuinely fresh realm.");
      process.exit(1);
    }

    step(6, "Enabling IGA");
    // Stamp iga.attestor=tide BEFORE toggling, so governance comes up in Tide mode (approvals
    // sealed by threshold signature) rather than Tideless mode (same quorum count, but enforced
    // by server logic with no cryptography, which a compromised host could bypass).
    const realmRep = await adminFetchOk(cfg, `/admin/realms/${cfg.realm}`);
    const attrs = { ...(realmRep.body.attributes || {}), "iga.attestor": "tide" };
    await adminFetchOk(cfg, `/admin/realms/${cfg.realm}`, {
      method: "PUT",
      json: { ...realmRep.body, attributes: attrs },
    });
    console.log("  iga.attestor = tide");

    // This endpoint reads the FORM parameter isIGAEnabled. A JSON body leaves the parameter
    // missing, and a missing parameter FAILS OPEN to true.
    const iga = await adminFetch(cfg, `/admin/realms/${cfg.realm}/tide-admin/toggle-iga`, {
      method: "POST",
      form: { isIGAEnabled: "true" },
    });
    console.log(`  toggle-iga -> ${iga.status}`);

    const check = await adminFetchOk(cfg, `/admin/realms/${cfg.realm}`);
    console.log(`  isIGAEnabled = ${check.body?.attributes?.isIGAEnabled}`);
  }

  step(7, "Draining outstanding change requests");
  await drainChangeRequests(cfg, { label: "post-setup" });

  /* ---------------- 8. verify roles actually exist ---------------- */
  step(8, "Verifying realm roles committed");
  // With IGA on, role creation returns 2xx and the role does NOT exist until committed.
  // Read back rather than trusting the status code.
  const required = [
    "_tide_enabled", "_tide_x.selfencrypt", "_tide_x.selfdecrypt",
    "coordinator", "doctor", "nurse", "hospital-admin",
    "clinical-staff", "response-team-infection-control", "careteam-patient-1",
    "emergency-responder",
  ];
  let roles = await listRealmRoles(cfg);
  let names = new Set(roles.map((r) => r.name));
  let missing = required.filter((r) => !names.has(r));

  if (missing.length) {
    console.log(`  missing after first drain: ${missing.join(", ")} — draining again`);
    await drainChangeRequests(cfg, { label: "roles" });
    roles = await listRealmRoles(cfg);
    names = new Set(roles.map((r) => r.name));
    missing = required.filter((r) => !names.has(r));
  }
  if (missing.length) {
    console.error(`  ERROR: roles still missing: ${missing.join(", ")}`);
    process.exit(1);
  }
  console.log(`  all ${required.length} required roles present`);
  const roleByName = new Map(roles.map((r) => [r.name, r]));

  /* ---------------- 9. create users and grant roles ---------------- */
  step(9, "Creating demo users");
  for (const u of USERS) {
    let user = await findUser(cfg, u.username);
    if (user) {
      console.log(`  ${u.username}: already exists`);
    } else {
      // tideInvitable + emailVerified:false mark the user as pending Tide enrollment.
      await adminFetch(cfg, `/admin/realms/${cfg.realm}/users`, {
        method: "POST",
        json: {
          username: u.username,
          email: u.email,
          firstName: u.firstName,
          lastName: u.lastName,
          enabled: true,
          emailVerified: false,
          attributes: { tideInvitable: ["true"] },
        },
      });
      await drainChangeRequests(cfg, { label: `create ${u.username}` });
      user = await findUser(cfg, u.username);
      if (!user) {
        console.error(`  ERROR: ${u.username} not queryable after commit.`);
        process.exit(1);
      }
      console.log(`  ${u.username}: created`);
    }
    u.id = user.id;
  }

  step(10, "Granting hospital roles (one role per request — see note)");
  // Batching several roles into one POST /role-mappings/realm returns 409 under IGA and applies
  // only the FIRST role in the array, silently. A single-role POST returns 204 and commits
  // cleanly. So grant one at a time, draining and reading back after each. Slower, correct.
  const wantedFor = (u) => [...u.appRoles, ...u.tagRoles, ...(u.encryptRole ? ["clinical-staff"] : [])];

  for (const u of USERS) {
    const wanted = wantedFor(u);

    for (const roleName of wanted) {
      const current = await adminFetch(cfg, `/admin/realms/${cfg.realm}/users/${u.id}/role-mappings/realm`);
      const have = new Set((current.body || []).map((r) => r.name));
      if (have.has(roleName)) continue; // idempotent: safe to re-run

      const role = roleByName.get(roleName);
      if (!role) throw new Error(`Role ${roleName} not found (needed by ${u.username})`);

      const res = await adminFetch(cfg, `/admin/realms/${cfg.realm}/users/${u.id}/role-mappings/realm`, {
        method: "POST",
        json: [{ id: role.id, name: role.name }],
      });
      if (!res.ok && res.status !== 204) {
        console.log(`    ${u.username} + ${roleName} -> ${res.status} ${String(res.text).slice(0, 160)}`);
      }
      await drainChangeRequests(cfg, { label: `${u.username}+${roleName}` });
    }
  }

  // Read back. A 2xx on the grant does not mean the mapping is live.
  console.log("  verifying granted roles:");
  let grantErrors = 0;
  for (const u of USERS) {
    const res = await adminFetch(cfg, `/admin/realms/${cfg.realm}/users/${u.id}/role-mappings/realm`);
    const have = new Set((res.body || []).map((r) => r.name));
    const gap = wantedFor(u).filter((r) => !have.has(r));
    if (gap.length) {
      console.log(`    ${u.username}: MISSING ${gap.join(", ")}`);
      grantErrors++;
    } else {
      console.log(`    ${u.username}: ok  [${wantedFor(u).join(", ")}]`);
    }
  }
  if (grantErrors) {
    console.error(`\n  ERROR: ${grantErrors} user(s) have missing roles. Re-run \`npm run init\` (idempotent).`);
    process.exit(1);
  }

  /* ---------------- 11. enrollment links ---------------- */
  step(11, "Generating Tide enrollment links");
  const links = [];
  for (const u of USERS) {
    const link = await getEnrollmentLink(cfg, u.id);
    links.push({ ...u, link });
    console.log(`  ${u.username}: ${link ? "ok" : "FAILED"}`);
  }

  const linksPath = resolve(PROJECT_ROOT, "tidecloak", "enrollment-links.md");
  writeFileSync(
    linksPath,
    [
      "# Tide enrollment links",
      "",
      "Tide has no admin-set passwords. Every user enrols themselves in a browser, which is where",
      "their threshold-protected credential is created. Open each link, choose a passphrase, and",
      "finish enrolment before trying to log in as that user.",
      "",
      "Links expire 12 hours after generation. Regenerate with `node scripts/invite-links.mjs`.",
      "",
      ...links.flatMap((u) => [
        `## ${u.username}`,
        "",
        `- **Who:** ${u.firstName} ${u.lastName}`,
        `- **Roles:** ${[...u.appRoles, ...u.tagRoles, ...(u.encryptRole ? ["clinical-staff"] : [])].join(", ") || "(none beyond defaults)"}`,
        `- **Role in the demo:** ${u.note}`,
        "",
        u.link ? `${u.link}` : "_link generation failed — re-run scripts/invite-links.mjs_",
        "",
      ]),
    ].join("\n"),
    "utf8"
  );
  console.log(`  written to ${linksPath}`);

  /* ---------------- 12. IdP console domain + sign ---------------- */
  step(12, "Pointing the Tide IdP at this realm's console, then signing IdP settings");
  const consoleOrigin = `${cfg.tidecloakUrl}/realms/${cfg.realm}/tide-console/`;
  const idp = await adminFetch(cfg, `/admin/realms/${cfg.realm}/identity-provider/instances/tide`);
  if (idp.ok) {
    const updated = {
      ...idp.body,
      config: { ...(idp.body.config || {}), CustomAdminUIDomain: consoleOrigin },
    };
    const put = await adminFetch(cfg, `/admin/realms/${cfg.realm}/identity-provider/instances/tide`, {
      method: "PUT",
      json: updated,
    });
    console.log(`  CustomAdminUIDomain = ${consoleOrigin} -> ${put.status}`);
  } else {
    console.log(`  WARNING: tide IdP not found (${idp.status}) — did setUpTideRealm succeed?`);
  }

  // ALWAYS required after any Tide IdP config change, or the enclave rejects the settings as
  // unsigned and login/encryption fail silently.
  const sign = await adminFetch(cfg, `/admin/realms/${cfg.realm}/vendorResources/sign-idp-settings`, {
    method: "POST",
  });
  console.log(`  sign-idp-settings -> ${sign.status}`);

  await drainChangeRequests(cfg, { label: "pre-flip" });

  /* ---------------- 13. tide-realm-admin is DEFERRED ---------------- */
  step(13, "tide-realm-admin: deferred until after Tide enrolment");
  // This grant cannot be made yet. TideCloak rejects it with:
  //   400 "Cannot assign tide-realm-admin: the target user is not linked to the Tide identity
  //        provider."
  // The role confers authority over Tide governance, so the user must first have a Tide identity
  // to be held accountable to — which only exists after they enrol in a browser. There is no way
  // to script around it, and that is the correct design.
  //
  // It is also a ONE-WAY DOOR: committing it flips the realm firstAdmin -> multiAdmin, after which
  // no change request can be approved from a script at all (409
  // MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE). So it must be the last governed write, which is exactly
  // where enrolment puts it anyway.
  //
  // `npm run finalize` performs it once hospital-admin has enrolled.
  console.log("  Requires the user to be linked to the Tide IdP first.");
  console.log("  Run `npm run finalize` after hospital-admin completes enrolment.");

  /* ---------------- 14. export the adapter ---------------- */
  step(14, "Exporting adapter JSON");
  const clientUuid = await getClientUuid(cfg, cfg.clientName);
  // Realm-level vendorResources endpoint with clientId as a QUERY PARAM. The per-client
  // Keycloak path (/clients/{id}/installation/providers/...) returns a minimal adapter with
  // no jwk/vendorId/homeOrkUrl. keycloak-oidc-keycloak-json is the only valid provider id.
  const adapter = await adminFetch(
    cfg,
    `/admin/realms/${cfg.realm}/vendorResources/get-installations-provider` +
      `?clientId=${clientUuid}&providerId=keycloak-oidc-keycloak-json`,
    { raw: true }
  );

  if (!adapter.ok) {
    console.error(`  ERROR: adapter export failed (${adapter.status}): ${adapter.text?.slice(0, 400)}`);
    process.exit(1);
  }

  mkdirSync(resolve(PROJECT_ROOT, "data"), { recursive: true });
  const adapterPath = resolve(PROJECT_ROOT, "data", "tidecloak.json");
  writeFileSync(adapterPath, adapter.text, "utf8");

  const parsed = JSON.parse(adapter.text);
  const hasJwk = !!parsed.jwk;
  const hasVendor = !!parsed.vendorId;
  const hasOrk = !!parsed.homeOrkUrl;
  const originKeys = Object.keys(parsed).filter((k) => k.startsWith("client-origin-auth-"));

  console.log(`  written to ${adapterPath}`);
  console.log(`  jwk: ${hasJwk}   vendorId: ${hasVendor}   homeOrkUrl: ${hasOrk}`);
  console.log(`  client-origin-auth entries: ${originKeys.length ? originKeys.join(", ") : "NONE"}`);

  if (!hasJwk || !hasVendor || !hasOrk) {
    console.error("\n  ERROR: adapter is missing Tide extensions.");
    console.error("  Do NOT hand-build this file and do NOT fall back to createRemoteJWKSet.");
    console.error("  A missing jwk means licensing or IGA did not complete. Fix it at the source.");
    process.exit(1);
  }

  console.log(`
=====================================================================
Bootstrap complete.

  Realm            ${cfg.realm}
  Client           ${cfg.clientName}
  Admin console    ${cfg.tidecloakUrl}/admin/master/console/
  Master admin     ${cfg.adminUser}  (password is in .env)

NEXT — these steps need a browser and cannot be scripted:

  1. Enrol the users. Open each link in tidecloak/enrollment-links.md and
     choose a passphrase. Tide has no admin-set passwords: the credential is
     created during enrolment, protected by threshold PRISM, and never stored
     as a hash anywhere. Enrol hospital-admin FIRST — step 2 depends on it.

  2. npm run finalize
     Grants tide-realm-admin to hospital-admin, which TideCloak refuses until
     that user has a linked Tide identity. This also creates the
     tide-realm-admin role policy that Forseti policy deployment needs.

  3. Deploy the Forseti contract and sign the encryption policy:
        npm run dev
        open http://localhost:3000/setup
     Signing needs a human approval in the Tide enclave popup, by design. A
     stolen automation credential must not be able to deploy a policy that
     governs who can decrypt patient data.
=====================================================================`);
}

main().catch((err) => {
  console.error("\nBootstrap failed:");
  console.error(err.message);
  process.exit(1);
});
