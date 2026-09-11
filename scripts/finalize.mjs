/**
 * Post-enrolment finalisation.
 *
 * Grants `tide-realm-admin` to hospital-admin. Split out of the main bootstrap because TideCloak
 * refuses the grant until the target user is linked to the Tide identity provider, and linking
 * happens in a browser. This is the point at which the realm flips firstAdmin -> multiAdmin.
 *
 * Run this AFTER hospital-admin has completed the enrolment link, and BEFORE deploying the
 * Forseti policy — `GET /iga/role-policies` returns an empty array until this grant exists,
 * because the tide-realm-admin policy is created as part of it, and policy deployment needs it.
 */

import {
  loadEnv,
  adminFetch,
  drainChangeRequests,
  getClientUuid,
  findUser,
} from "./lib/tidecloak.mjs";

const cfg = loadEnv();

console.log("Finalising realm:", cfg.realm);

/* --- 1. confirm enrolment --- */
const admin = await findUser(cfg, "hospital-admin");
if (!admin) {
  console.error("hospital-admin does not exist. Run `npm run init` first.");
  process.exit(1);
}

const linked = !!admin.attributes?.tideUserKey?.[0];
const vuid = admin.attributes?.vuid?.[0];

console.log(`  hospital-admin linked to Tide IdP: ${linked ? "yes" : "NO"}`);
if (vuid) console.log(`  vuid: ${vuid}`);

if (!linked) {
  console.error(`
hospital-admin has not completed Tide enrolment yet.

Open the hospital-admin link in tidecloak/enrollment-links.md and finish enrolment,
then run this again. If the link has expired, regenerate it with:

    npm run invite
`);
  process.exit(1);
}

/* --- 2. drain anything outstanding BEFORE the flip --- */
console.log("\nDraining outstanding change requests before the multiAdmin flip");
await drainChangeRequests(cfg, { label: "pre-flip" });

/* --- 3. grant tide-realm-admin --- */
console.log("\nGranting tide-realm-admin to hospital-admin");
console.log("  This is a one-way door: the realm becomes multiAdmin and later governed");
console.log("  changes will require a human enclave approval.");

const rmUuid = await getClientUuid(cfg, "realm-management");

const existing = await adminFetch(
  cfg,
  `/admin/realms/${cfg.realm}/users/${admin.id}/role-mappings/clients/${rmUuid}`
);
if ((existing.body || []).some((r) => r.name === "tide-realm-admin")) {
  console.log("  already granted — nothing to do");
} else {
  const roleRes = await adminFetch(
    cfg,
    `/admin/realms/${cfg.realm}/clients/${rmUuid}/roles/tide-realm-admin`
  );
  if (!roleRes.ok) {
    console.error(`  tide-realm-admin role lookup failed (${roleRes.status})`);
    process.exit(1);
  }

  const grant = await adminFetch(
    cfg,
    `/admin/realms/${cfg.realm}/users/${admin.id}/role-mappings/clients/${rmUuid}`,
    { method: "POST", json: [roleRes.body], raw: true }
  );
  console.log(`  grant -> ${grant.status}`);
  if (!grant.ok && grant.status !== 204) {
    console.error(`  body: ${grant.text?.slice(0, 400)}`);
    process.exit(1);
  }

  await drainChangeRequests(cfg, { label: "grant tide-realm-admin" });

  const after = await adminFetch(
    cfg,
    `/admin/realms/${cfg.realm}/users/${admin.id}/role-mappings/clients/${rmUuid}`
  );
  const ok = (after.body || []).some((r) => r.name === "tide-realm-admin");
  console.log(`  verified: ${ok ? "granted" : "STILL MISSING"}`);
  if (!ok) {
    console.error("  The grant did not commit. Check the admin console Change Requests view.");
    process.exit(1);
  }
}

/* --- 4. confirm the role policy Forseti deployment needs --- */
console.log("\nChecking for the tide-realm-admin role policy (needed to deploy a Forseti policy)");
const rp = await adminFetch(cfg, `/admin/realms/${cfg.realm}/iga/role-policies`);
const policies = Array.isArray(rp.body) ? rp.body : [];
console.log(`  GET /iga/role-policies -> ${rp.status}, ${policies.length} record(s)`);
for (const p of policies) {
  console.log(`   - ${p.name}  policy=${p.policy ? `${String(p.policy).length}b base64` : "EMPTY"}`);
}

const adminPolicies = policies.filter((p) => p.name === "tide-realm-admin");
if (adminPolicies.length !== 1) {
  console.warn(`
  WARNING: expected exactly one policy named "tide-realm-admin", found ${adminPolicies.length}.
  Policy deployment attaches this policy by NAME and must not fall back to index 0 —
  with more than one record, index 0 silently deploys under the wrong authority.`);
} else {
  console.log("  Found it. Forseti policy deployment can proceed.");
}

/* --- 5. enrolment status of everyone else --- */
console.log("\nEnrolment status of all demo users:");
for (const u of ["coordinator", "nurse-a", "doctor-a", "doctor-b", "hospital-admin"]) {
  const user = await findUser(cfg, u);
  const isLinked = !!user?.attributes?.tideUserKey?.[0];
  console.log(`  ${u.padEnd(16)} ${isLinked ? "enrolled" : "NOT enrolled"}`);
}

console.log(`
Done. Next:
    npm run dev
    open http://localhost:3000/setup     (deploy the Forseti contract + sign the policy)
`);
