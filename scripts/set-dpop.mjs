/**
 * Flip DPoP on or off for the app client, in LOCKSTEP with the client-side config.
 *
 *   node scripts/set-dpop.mjs on
 *   node scripts/set-dpop.mjs off
 *
 * WHY THIS SCRIPT EXISTS
 *
 * DPoP binds an access token to a key pair held by the browser, so a stolen token is useless
 * without it. Tide treats it as the only recommended configuration, and our realm template turns
 * it on server-side. But it is a BIDIRECTIONAL requirement:
 *
 *   server on  + client off -> token endpoint returns 400 "DPoP proof is missing". Login broken.
 *   server off + client on  -> SDK init fails: the realm does not advertise DPoP support.
 *
 * So the two halves must be changed together. This script owns the server half; the client half is
 * `NEXT_PUBLIC_TIDE_DPOP` in .env, read by src/app/providers.tsx and src/lib/tideJWT.ts.
 *
 * TIMING CONSTRAINT: changing a client attribute is a governed write. Run this BEFORE
 * `npm run finalize` grants tide-realm-admin. After that grant the realm is multiAdmin and this
 * needs a human enclave approval in the admin console instead.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import {
  PROJECT_ROOT,
  loadEnv,
  adminFetch,
  drainChangeRequests,
  getClientUuid,
} from "./lib/tidecloak.mjs";

const mode = (process.argv[2] || "").toLowerCase();
if (mode !== "on" && mode !== "off") {
  console.error("Usage: node scripts/set-dpop.mjs <on|off>");
  process.exit(1);
}
const enable = mode === "on";

const cfg = loadEnv();

/* --- guard: turning DPoP on without the relay page guarantees a broken login --- */
const relay = resolve(PROJECT_ROOT, "public", "tide_dpop_auth.html");
if (enable) {
  if (!existsSync(relay)) {
    console.error(`
Refusing to enable DPoP: public/tide_dpop_auth.html is missing.

The Tide enclave loads that page from our origin during login to prove DPoP key
possession. It is NOT shipped in the @tidecloak/* npm packages and the SDK never
references the path, so nothing in this project can supply it.

Without it, enabling DPoP fails at login with:
    TIDE-SWE-UNHANDLED  /  "Popup DPoP verification failed to load"

Obtain it from the Tide team, drop it in public/, and re-run. Verify the copy first —
two versions circulate and the older one is broken:

    sha256  9d7844b938f0a2565fa910d3d30e9b8797cbfd6e0b73d59d804169a089aea757
    size    9120 bytes
    must contain "window.opener" (3 occurrences)

A copy that posts only to window.parent is the STALE one. window.parent is right in an
iframe but wrong in the popup fallback, where window.parent === window, so the page
messages itself and the opener never hears back.
`);
    process.exit(1);
  }

  // Verify the copy rather than trusting it.
  const { createHash } = await import("node:crypto");
  const buf = readFileSync(relay);
  const sha = createHash("sha256").update(buf).digest("hex");
  const KNOWN_GOOD = "9d7844b938f0a2565fa910d3d30e9b8797cbfd6e0b73d59d804169a089aea757";
  const openerCount = (buf.toString("utf8").match(/window\.opener/g) || []).length;

  console.log(`  relay page: ${buf.length} bytes, sha256 ${sha.slice(0, 16)}...`);
  console.log(`  window.opener occurrences: ${openerCount}`);

  if (sha !== KNOWN_GOOD) {
    console.warn(`  WARNING: sha256 does not match the known-good copy (${KNOWN_GOOD.slice(0, 16)}...).`);
    if (openerCount === 0) {
      console.error("  It contains no window.opener, so this is the STALE copy. Refusing.");
      process.exit(1);
    }
    console.warn("  It does handle window.opener, so it may simply be a newer revision. Continuing.");
  }
}

/* --- server half: the client attribute --- */
console.log(`\nSetting dpop.bound.access.tokens = ${enable} on client "${cfg.clientName}"`);

const clientUuid = await getClientUuid(cfg, cfg.clientName);
const clientRes = await adminFetch(cfg, `/admin/realms/${cfg.realm}/clients/${clientUuid}`);
if (!clientRes.ok) {
  console.error(`  Could not read client (${clientRes.status})`);
  process.exit(1);
}

const current = clientRes.body.attributes?.["dpop.bound.access.tokens"];
console.log(`  current value: ${current ?? "(unset)"}`);

if (String(current) === String(enable)) {
  console.log("  already correct on the server side");
} else {
  const updated = {
    ...clientRes.body,
    attributes: {
      ...(clientRes.body.attributes || {}),
      "dpop.bound.access.tokens": String(enable),
    },
  };
  const put = await adminFetch(cfg, `/admin/realms/${cfg.realm}/clients/${clientUuid}`, {
    method: "PUT",
    json: updated,
    raw: true,
  });
  console.log(`  PUT client -> ${put.status}`);
  if (put.status === 409 || /MULTIADMIN/i.test(put.text || "")) {
    console.error(`
  The realm is already multiAdmin, so this change needs a human enclave approval:
      ${cfg.tidecloakUrl}/admin/${cfg.realm}/console/  ->  Change Requests
`);
    process.exit(1);
  }
  await drainChangeRequests(cfg, { label: `dpop=${enable}` });

  const after = await adminFetch(cfg, `/admin/realms/${cfg.realm}/clients/${clientUuid}`);
  const now = after.body?.attributes?.["dpop.bound.access.tokens"];
  console.log(`  verified: dpop.bound.access.tokens = ${now}`);
  if (String(now) !== String(enable)) {
    console.error("  The change did not commit. Check the admin console Change Requests view.");
    process.exit(1);
  }
}

/* --- client half: .env --- */
const envPath = resolve(PROJECT_ROOT, ".env");
let env = existsSync(envPath) ? readFileSync(envPath, "utf8") : "";
const line = `NEXT_PUBLIC_TIDE_DPOP=${enable ? "on" : "off"}`;

if (/^NEXT_PUBLIC_TIDE_DPOP=.*$/m.test(env)) {
  env = env.replace(/^NEXT_PUBLIC_TIDE_DPOP=.*$/m, line);
} else {
  env = env.replace(/\s*$/, "") + "\n" + line + "\n";
}
writeFileSync(envPath, env, "utf8");
console.log(`  .env updated: ${line}`);

console.log(`
DPoP is now ${enable ? "ENABLED" : "DISABLED"} on both sides.

Restart the dev server so the client picks up the change:
    npm run dev
${
  enable
    ? `
Then confirm the relay is served correctly — read the header, do not reason about it:
    curl.exe -sS -D - -o NUL "http://localhost:3000/tide_dpop/iss/6161/aud/6262/tide_dpop_auth.html"
  want: HTTP 200
        Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'
        Allow-CSP-From: *
`
    : `
NOTE: access tokens are now plain bearer tokens. A stolen token can be replayed from
another device. This is a real, HIGH-severity weakening (SG-03) and is recorded as the
single known security gap in this project. See LEARNING.md and docs/SECURITY-GAPS.md.
`
}`);
