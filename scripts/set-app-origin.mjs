/**
 * Change the app's origin (scheme://host:port) everywhere it is registered.
 *
 *     node scripts/set-app-origin.mjs http://localhost:3100
 *
 * An origin change touches four things, and missing any one of them breaks login in a way that does
 * not name the origin:
 *
 *   1. the client's redirectUris          -> otherwise TideCloak refuses with "Invalid redirect_uri"
 *   2. the client's webOrigins            -> otherwise the browser reports a CORS failure
 *   3. sign-idp-settings                  -> ALWAYS required after a Tide IdP/origin change, or the
 *                                            enclave rejects the settings as unsigned and login
 *                                            fails silently
 *   4. a fresh adapter export             -> the adapter carries one ORK-signed
 *                                            `client-origin-auth-<origin>` entry PER allowed origin,
 *                                            and enclave initialisation fails without a matching one
 *
 * TIMING: these are governed writes. Run BEFORE `npm run finalize` grants tide-realm-admin. After
 * that the realm is multiAdmin and each change needs a human enclave approval.
 */

import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import {
  PROJECT_ROOT,
  loadEnv,
  adminFetch,
  drainChangeRequests,
  getClientUuid,
} from "./lib/tidecloak.mjs";

const raw = process.argv[2];
if (!raw) {
  console.error("Usage: node scripts/set-app-origin.mjs <origin>   e.g. http://localhost:3100");
  process.exit(1);
}

let origin;
try {
  const u = new URL(raw);
  origin = `${u.protocol}//${u.host}`;
} catch {
  console.error(`Not a valid origin: ${raw}`);
  process.exit(1);
}

const cfg = loadEnv();
console.log(`Setting the app origin to ${origin}\n`);

/* --- 1 + 2. redirect URIs and web origins --- */
const clientUuid = await getClientUuid(cfg, cfg.clientName);
const clientRes = await adminFetch(cfg, `/admin/realms/${cfg.realm}/clients/${clientUuid}`);
if (!clientRes.ok) {
  console.error(`Could not read client (${clientRes.status})`);
  process.exit(1);
}

const redirectUris = [
  origin,
  `${origin}/*`,
  `${origin}/silent-check-sso.html`,
  `${origin}/auth/redirect`,
];

console.log("Registering:");
for (const u of redirectUris) console.log(`  redirectUri  ${u}`);
console.log(`  webOrigin    ${origin}`);

const put = await adminFetch(cfg, `/admin/realms/${cfg.realm}/clients/${clientUuid}`, {
  method: "PUT",
  json: { ...clientRes.body, redirectUris, webOrigins: [origin] },
  raw: true,
});
console.log(`\n  PUT client -> ${put.status}`);
if (put.status === 409 || /MULTIADMIN/i.test(put.text || "")) {
  console.error(`
  The realm is multiAdmin, so this needs a human enclave approval at
      ${cfg.tidecloakUrl}/admin/${cfg.realm}/console/  ->  Change Requests
`);
  process.exit(1);
}
await drainChangeRequests(cfg, { label: "origin change" });

const verify = await adminFetch(cfg, `/admin/realms/${cfg.realm}/clients/${clientUuid}`);
console.log(`  verified redirectUris: ${(verify.body?.redirectUris || []).join(", ")}`);
console.log(`  verified webOrigins  : ${(verify.body?.webOrigins || []).join(", ")}`);

/* --- 3. re-sign the IdP settings --- */
console.log("\nRe-signing IdP settings (required after any origin change)");
const sign = await adminFetch(cfg, `/admin/realms/${cfg.realm}/vendorResources/sign-idp-settings`, {
  method: "POST",
});
console.log(`  sign-idp-settings -> ${sign.status}`);
if (!sign.ok) {
  console.error(`  FAILED: ${sign.text?.slice(0, 300)}`);
  console.error("  Without this the enclave treats the settings as unsigned and login fails silently.");
  process.exit(1);
}

/* --- 4. re-export the adapter --- */
console.log("\nRe-exporting the adapter so it carries a client-origin-auth entry for this origin");
const adapter = await adminFetch(
  cfg,
  `/admin/realms/${cfg.realm}/vendorResources/get-installations-provider` +
    `?clientId=${clientUuid}&providerId=keycloak-oidc-keycloak-json`,
  { raw: true }
);
if (!adapter.ok) {
  console.error(`  export failed (${adapter.status}): ${adapter.text?.slice(0, 300)}`);
  process.exit(1);
}

mkdirSync(resolve(PROJECT_ROOT, "data"), { recursive: true });
writeFileSync(resolve(PROJECT_ROOT, "data", "tidecloak.json"), adapter.text, "utf8");

const parsed = JSON.parse(adapter.text);
const originKeys = Object.keys(parsed).filter((k) => k.startsWith("client-origin-auth-"));
console.log(`  jwk: ${!!parsed.jwk}  vendorId: ${!!parsed.vendorId}  homeOrkUrl: ${!!parsed.homeOrkUrl}`);
console.log(`  origin entries: ${originKeys.join(", ") || "NONE"}`);

const wanted = `client-origin-auth-${origin}`;
if (!originKeys.includes(wanted)) {
  console.error(`
  WARNING: the adapter has no "${wanted}" entry.
  The SDK selects the entry matching window.location.origin and enclave init fails without it.
  Confirm the webOrigins change committed, then re-run.
`);
} else {
  console.log(`  found ${wanted}`);
}

/* --- .env --- */
const envPath = resolve(PROJECT_ROOT, ".env");
let env = existsSync(envPath) ? readFileSync(envPath, "utf8") : "";
if (/^CLIENT_APP_URL=.*$/m.test(env)) {
  env = env.replace(/^CLIENT_APP_URL=.*$/m, `CLIENT_APP_URL=${origin}`);
} else {
  env = env.replace(/\s*$/, "") + `\nCLIENT_APP_URL=${origin}\n`;
}
writeFileSync(envPath, env, "utf8");
console.log(`\n  .env updated: CLIENT_APP_URL=${origin}`);

const port = new URL(origin).port || "3000";
console.log(`
Done. Restart the dev server, and make sure it binds this port:

    npm run dev        (package.json already passes -p ${port})

Then confirm the app — not something else — is answering:

    Invoke-WebRequest http://localhost:${port}/api/config
`);
