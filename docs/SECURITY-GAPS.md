# Tide Security Gaps — Hospital Emergency Platform

**Scope:** Static review of the implemented repository and the configured local TideCloak PoC. No live security probes or enrollment changes were performed. The coordinator enrollment failure is a Tide-side unresolved issue and is not treated as an application authorization finding.

## Trust architecture

- **Identity:** TideCloak/Tide browser login. The realm is configured for Tide mode (`iga.attestor=tide`); user records and realm roles remain in TideCloak, while Tide identity linking adds `tideUserKey`.
- **Token authority:** The application verifies the embedded adapter JWKS locally. Tide tokens are intended to be threshold-backed; the complete signing authority is not held by the Next.js process.
- **API authorization:** `withAuth` calls `verifyTideJWT` before every protected API handler, then applies route-specific realm-role checks. The public configuration endpoint is intentionally unauthenticated. Client-side `hasRealmRole` checks are UI gating only.
- **Sensitive data:** Alert, patient, and report content is encrypted in the browser with policy bytes before storage. SQLite still contains ciphertext, tags, IDs, timestamps, usernames, recipient ACLs, care-team membership, and audit entries.

## Findings and remaining gaps

### [HIGH] SG-03 — DPoP is disabled, so access tokens are bearer tokens

- **Trust concentration:** Any place an access token is exposed, including a browser, proxy, log, or extension.
- **Evidence:** `src/lib/tideJWT.ts` sets `DPOP_ENABLED` from `NEXT_PUBLIC_TIDE_DPOP`; the current project state has DPoP set to `off`. `scripts/set-dpop.mjs` refuses to enable it without the verified relay asset. [VERIFIED configuration/code state]
- **Failure scenario:** A stolen unexpired access token can be replayed from another device. The server verifies the JWT but does not require proof of possession while DPoP is off.
- **Tide capability:** DPoP token binding, with client/server/TideCloak configuration in lockstep. [VERIFIED capability; deployment not complete]
- **Remediation:** Obtain and verify `public/tide_dpop_auth.html`, run `node scripts/set-dpop.mjs on`, and test login and API calls again.
- **Limit:** DPoP does not protect a live browser session that an attacker fully controls, and it does not fix XSS.

### [HIGH] SG-08 — Standing TideCloak bootstrap credentials are used by application request handlers

- **Trust concentration:** `KC_BOOTSTRAP_ADMIN_PASSWORD` and the server processes that can read it.
- **Evidence:** `src/app/api/users/route.ts`, `src/app/api/policy/contract/route.ts`, and `src/app/api/policy/admin-policy/route.ts` obtain a master/admin token through the password grant using `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD`. [VERIFIED code]
- **Failure scenario:** Compromise of the Next.js runtime, environment, or logs can expose a standing credential capable of privileged TideCloak REST operations. The user route also falls back to username `admin` when the username variable is absent.
- **Tide capability:** Short-lived server-side delegation for user-driven admin operations. [VERIFIED capability mapping]
- **Remediation:** Remove the password-grant dependency from request handlers; use least-privilege, short-lived delegation or a separately protected administrative process. Remove unsafe defaults and rotate the current secret before shared deployment.
- **Limit:** Delegation does not solve autonomous machine identity, secret rotation, container compromise, or general infrastructure secret management by itself.

### [HIGH] SG-14 — The application audit trail is tamperable and partly client-reported

- **Trust concentration:** The SQLite file and the application/administrator with write access to it.
- **Evidence:** `src/lib/db.ts` stores `access_log` in the same local database as application data. `src/app/api/audit/route.ts` accepts `outcome` and `detail` from the browser and explicitly describes the result as “not trustworthy evidence.” [VERIFIED code]
- **Failure scenario:** A database writer can alter or delete access entries. A malicious client can submit misleading audit outcomes, although this does not bypass the ORK decision that already occurred.
- **Tide capability:** Tide IGA can make governed administrative authorization records tamper-evident in Tide mode. [VERIFIED capability, but not a replacement for this application event log]
- **Remediation:** Separate diagnostic client reports from security evidence; add an append-only or externally protected audit sink for privileged actions; restrict database write access and monitor integrity.
- **Limit:** Tide does not make arbitrary SQLite application events immutable, and the current browser-reported decrypt result is not proof of what the ORKs decided.

### [MEDIUM] SG-06 residual — Sensitive metadata remains readable even though content is encrypted

- **Trust concentration:** Anyone who obtains the SQLite database and its metadata tables.
- **Evidence:** `src/lib/db.ts` stores `created_by`, usernames, recipient rows, care-team rows, IDs, timestamps, tags, and policy deployment metadata in plaintext. The same file documents this limitation. [VERIFIED schema/code]
- **Failure scenario:** A stolen database does not reveal alert/report content, but it can reveal who was involved, which team tag was used, patient identifiers such as `patient-1`, and timing/relationship metadata.
- **Tide capability:** Policy-governed E2EE protects the encrypted payloads and enforces role access at the ORKs. [VERIFIED implementation/capability]
- **Remediation:** Minimize identifiers and timestamps, consider encrypting sensitive metadata where the product can tolerate it, and document the remaining metadata exposure in the threat model.
- **Limit:** Tide encryption does not automatically protect application indexes or ACL rows that the server needs to query.

### [MEDIUM] SG-16 residual — Policy setup is protected, but policy storage is not independently validated as a security boundary

- **Trust concentration:** The `hospital-admin` session and the Next.js `/api/policy` storage path.
- **Evidence:** `src/app/api/policy/route.ts` accepts `policyB64` and `contractId` from an authenticated `hospital-admin` and stores them in SQLite. The setup UI obtains the signed policy through Tide/ORK approval, but the storage route is an application persistence step. [VERIFIED code; runtime signature validation not completed]
- **Failure scenario:** A hospital-admin or database writer could replace the stored policy and cause denial of service or policy drift. The replacement should not grant cryptographic access if the ORKs reject an invalid signature, but this specific behavior has not yet been verified in the live PoC.
- **Tide capability:** Forseti policy signing and ORK-side policy verification; human enclave approval is already part of `/setup`. [VERIFIED implementation/capability]
- **Remediation:** Validate policy structure/signature and exact deployed contract identity before storage; verify a tampered policy is rejected by the ORKs; restrict and monitor policy replacement.
- **Limit:** Tide does not automatically protect arbitrary application database writes, and this report does not claim runtime tamper rejection until it is tested.

## Controls implemented, not currently classified as gaps

- **SG-04/SG-05:** The implemented `/api` routes use `withAuth`; `src/lib/api-auth.ts` verifies JWTs and route handlers apply role gates. This is a static code finding, not a substitute for a future exhaustive automated route test.
- **SG-10/SG-13:** `src/lib/tideJWT.ts` uses `jose` with the embedded local JWKS and validates issuer, `azp`, expiry, issuance time, and signature. It does not use a remote JWKS or trust an unverified decoded token.
- **SG-06 core content protection:** `src/lib/crypto-client.ts` passes signed policy bytes directly to `IAMService.doEncrypt`/`doDecrypt`; `src/lib/db.ts` has no server-side decrypt path; `forseti/HospitalAccessPolicy.cs` checks the encrypting role and tag-derived decrypt role. Successful browser encrypt/decrypt and attack demonstrations remain to be verified.
- **IGA governance:** The live realm was configured with `iga.attestor=tide`, but full multi-user governance and the resulting runtime guarantees still need the pending enrollment/finalization and policy tests described in `BACKLOG.md`.

## Not addressed by Tide

These are application or operational controls and must not be presented as Tide fixes:

- SQL/NoSQL or command injection
- XSS, CSRF, and output-encoding defects
- SSRF, path traversal, and unsafe file handling
- Missing API rate limiting, brute-force controls, and abuse prevention
- Vulnerable dependencies and supply-chain maintenance
- Container, host, port, TLS, backup, and secret-storage hardening
- General logging, monitoring, alerting, and incident response
- IDOR or business-workflow flaws beyond the implemented role/ACL checks
- Database availability, backup confidentiality, and corruption recovery

## Verification status

The build and route smoke checks have passed, and the local Tide adapter/IGA configuration has been inspected. The following remain unverified in the running PoC: successful coordinator identity linking, successful browser enclave approval and signed-policy deployment, real shared encryption/decryption, DPoP operation, and the stolen-database/malicious-ACL attack outputs.

The enrollment failure is specifically recorded as: coordinator account exists, expected roles exist, `tideUserKey` is not linked, and the local TideCloak container logs contain no signature-verification rejection. It is left for Tide-side investigation rather than speculatively attributed to this application.
