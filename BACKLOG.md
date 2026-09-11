# Hospital Emergency Platform Development Backlog

This is the backlog for the implementation that exists in this repository. It deliberately separates completed code from work that still requires browser interaction, live Tide verification, or hardening. The coordinator enrollment/signature-verification issue is recorded as blocked and is not changed here.

## Current state

Implemented: Next.js App Router UI and API routes; local SQLite persistence; TideCloak OIDC integration; server-side JWT verification with the embedded adapter JWKS; role-gated alert, patient, report, policy, user, and audit APIs; browser-side policy-governed encryption/decryption calls; Forseti contract source; administrator policy setup flow; attack demonstration scripts; `ARCHITECTURE.md`; and `USER-FLOW.md`.

Verified build/runtime work: `npm run build` has passed, the app runs on port `3100`, TideCloak is running as `tidecloak-hospital`, the realm is licensed with `iga.attestor=tide`, and the adapter contains `jwk`, `vendorId`, and `homeOrkUrl`.

Not yet demonstrated end-to-end: all users successfully linking Tide identities, the coordinator link failure, successful browser policy signing, successful shared encrypt/decrypt for the alert and report paths, and both attack scripts producing their expected runtime results.

## Priority backlog

### P0 — Required to claim a working PoC

1. **Resolve coordinator Tide identity enrollment** — **Blocked: Tide-side investigation/user action**
   - The `coordinator` TideCloak user exists and has its realm roles, but `tideUserKey` is still not linked.
   - Tide reports `security check (signature verification) didn't pass`; no corresponding rejection is present in the local container logs.
   - Do not alter the application to work around this. Generate/use a fresh enrollment link and escalate the Tide-side verification failure if it persists.

2. **Complete browser enrollment for all demo users** — **Blocked: browser/user action**
   - Verify `hospital-admin`, `coordinator`, `nurse-a`, `doctor-a`, and `doctor-b` have linked Tide identities.
   - Re-run `npm run diagnose` after enrollment. Do not treat a created username or assigned role as equivalent to a linked Tide identity.

3. **Finalize governed role changes** — **Blocked until enrollment is complete**
   - Run `npm run finalize` after the required users are linked.
   - Confirm pending IGA change requests are committed and refresh user tokens before testing role-dependent behavior.

4. **Deploy and sign the Forseti policy** — **Blocked: administrator browser approval**
   - Open `/setup` as `hospital-admin`.
   - Confirm the contract upload, admin-policy retrieval, Tide enclave approval, ORK threshold signature, and signed-policy storage all complete.
   - Verify `GET /api/policy` returns the stored signed policy and that the contract hash matches the deployed source.

5. **Run the real browser crypto smoke test** — **Blocked until policy and identities are ready**
   - Coordinator encrypts an alert tagged `hosp:response-team-infection-control`.
   - A response-team user decrypts it.
   - A user without that tag role receives an ORK denial.
   - Nurse/doctor encrypts a report tagged `hosp:careteam-patient-1` and an authorised care-team user decrypts it.
   - Record actual results in `LEARNING.md`; do not infer success from a successful API POST.

6. **Verify the attack demonstrations** — **Blocked until real ciphertext exists**
   - Run `npm run attack:steal-db` and confirm the database exposes ciphertext rather than sensitive alert/report plaintext.
   - Run `npm run attack:admin-escalate` and confirm that changing the SQLite ACL does not make the ORKs decrypt for the attacker.
   - Capture the exact output and document any limitation, especially visible usernames, tags, timestamps, and ACL metadata.

### P1 — Security and operational hardening

7. **Enable DPoP after the relay asset is available** — **Currently blocked by missing asset**
   - Obtain and verify the required `public/tide_dpop_auth.html` asset before enabling it.
   - Run `node scripts/set-dpop.mjs on`, then verify client configuration, TideCloak client configuration, and server `cnf.jkt` enforcement remain in lockstep.
   - Re-test login and protected API calls. The current bearer-token mode is a documented HIGH-severity gap.

8. **Remove standing bootstrap-admin credentials from request handlers**
   - `src/app/api/users/route.ts`, `src/app/api/policy/contract/route.ts`, and `src/app/api/policy/admin-policy/route.ts` obtain admin tokens with `KC_BOOTSTRAP_ADMIN_USERNAME`/`KC_BOOTSTRAP_ADMIN_PASSWORD`.
   - Replace this design with a short-lived, least-privilege delegation or a separately protected administration service/process.
   - Ensure no default fallback (`admin`) is usable outside local development and rotate the current bootstrap secret before any shared deployment.

9. **Make policy persistence validate its input and deployment identity**
   - `POST /api/policy` should validate the policy structure/signature and bind it to the currently live contract id before storing it.
   - Preserve the existing ORK verification as the cryptographic authority, but reject malformed, stale, or oversized values early to reduce denial-of-service and operator-error cases.

10. **Harden the audit model**
    - `access_log` is local SQLite data and `POST /api/audit` accepts client-reported decrypt outcomes; the route explicitly treats it as convenience evidence, not a security control.
    - Separate security evidence from user-facing diagnostics, make entries append-only at the database/operational layer, and add an external protected sink for privileged actions if audit integrity matters.

11. **Add input and abuse controls to the API**
    - Add schema validation, payload-size limits, identifier constraints, rate limiting, and consistent error handling to all JSON route handlers.
    - Review the dynamic alert, patient, report, policy, and audit inputs for IDOR and workflow abuse. These are application controls, not Tide controls.

### P2 — Verification, maintainability, and delivery

12. **Add automated route authorization tests**
    - Cover missing/invalid/expired tokens, wrong `azp`, missing roles, recipient ACLs, care-team ACLs, and policy-admin routes.
    - Enumerate every `/api` route so new routes cannot silently skip `withAuth`.

13. **Add a deterministic end-to-end demo checklist or harness**
    - Keep browser-only steps explicit: enrollment, enclave approval, token refresh, encrypt/decrypt, and denial tests.
    - Keep destructive/reset operations separate from the normal smoke path. Note that `package.json` references `scripts/reset-db.mjs`, which is not present in the current tree and must be added or the script removed.

14. **Review database metadata exposure**
    - Ciphertext protects alert/report content, but SQLite still contains usernames, authors, recipient lists, care-team membership, tags, IDs, and timestamps.
    - Decide which metadata is acceptable for the PoC and encrypt or minimize any metadata that must also be protected.

15. **Dependency and deployment review**
    - Run dependency auditing and define update policy for pinned Tide packages, Next.js, React, `better-sqlite3`, and `jose`.
    - Document production requirements: HTTPS, secret storage, SQLite file permissions/backups, container hardening, and TideCloak/ORK availability.

16. **Keep documentation synchronized with runtime evidence**
    - Update `LEARNING.md` with enrollment, policy-signing, and crypto-test outcomes.
    - Update `ARCHITECTURE.md` and `USER-FLOW.md` only when the implementation changes.
    - Do not claim full MVP success until P0 items 1–6 have evidence.

## Suggested execution order

1. Resolve coordinator enrollment and finish the remaining browser enrollments.
2. Run `npm run finalize` and verify IGA state/token refresh.
3. Complete `/setup` and deploy the signed policy.
4. Run the browser crypto and denial matrix.
5. Run both attack scripts and record results.
6. Enable DPoP when the verified relay asset is available.
7. Remove standing admin credentials and harden audit/input handling.
8. Add automated tests and complete deployment/dependency documentation.
