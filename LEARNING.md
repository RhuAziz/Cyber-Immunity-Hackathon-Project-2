# Tide/TideCloak Learning Log

This file records what we learned, got wrong, and had to research while integrating
Tide/TideCloak into the Hospital Emergency Alerting and Reporting Platform.

**Rule for this file:** failed approaches are *not* deleted once a solution is found. The point
is to preserve the reasoning, including the wrong turns. If an entry says "we assumed X and X was
false", that entry stays.

**Status tags** used below, borrowed from the Tide pack's own convention:

- `VERIFIED` — confirmed against Tide documentation, the Tide MCP knowledge pack, or observed
  behaviour of a running instance.
- `INFERRED` — strongly implied but not directly confirmed.
- `ASSUMED` — our own operating decision where sources are silent. Treat as suspect.
- `UNRESOLVED` — still open.

---

## 2026-09-10

### Task

Project inception. Decide the technology stack and, before writing any code, resolve which Tide
encryption model this project requires.

### Issue

There is no single "Tide encryption" feature. Tide has **two** encryption models with different
key binding, different SDK call paths, and different role requirements — and they are **not
interchangeable**:

| Model | Key binding | Who can decrypt | SDK path |
|---|---|---|---|
| Self-encryption | Encrypting user's own identity (CVK) | **Only the encrypting user** | `doEncrypt(data)` from `useTideCloak()`, no policy bytes |
| Policy-governed VVK | Organisational key across ORKs | **Anyone whose doken satisfies a Forseti contract** | `IAMService.doEncrypt(data, signedPolicyBytes)` |

The Tide pack flags this as invariant **I-17** (Scenario-Disambiguation Gate) and warns that
picking wrong is not an incremental mistake: *"Rework is not incremental — it is a full redo of the
affected layer."* Self-encryption cannot be upgraded to shared encryption later.

The trap is that self-encryption is the more obvious, better-documented path, and it *appears* to
work: you encrypt, you decrypt, tests pass. It fails only when a **second** user tries to read the
data — which in this project is the entire point.

### Cause

Our requirements are unambiguous about needing shared encryption once you look for it:

- A **coordinator** encrypts an emergency alert. **Six different staff members** must decrypt it.
- **Nurse A** encrypts a patient incident report. **Doctor A** must decrypt it.

In both cases the encryptor and the decryptor are different people. Self-encryption would make the
alert readable only by the coordinator who wrote it, and the report readable only by the nurse who
filed it — which would fail success criteria 5, 10, and 15 while superficially looking like
working encryption.

There is a specific documented anti-pattern for the mistake we were at risk of making (AP-26):
renaming the roles from `selfencrypt`/`selfdecrypt` to `encrypt`/`decrypt` and expecting that to
enable cross-user decryption. **The role suffix does not change the encryption model.** What
determines the model is whether the SDK call passes signed policy bytes.

### Attempted Solutions

1. Asked the pack's scenario resolver to match our description. It returned **two** candidate
   scenarios (`encrypted-communication` and `iga-admin-governance`) and explicitly refused to pick,
   citing I-17. Correct behaviour on its part, but it did not resolve our question.
2. Read the `encrypted-communication` disambiguation note, which says to use
   `organisation-password-manager` instead when the app only *stores* encrypted data with no
   real-time streaming. That is us: we store encrypted alerts and reports, no chat/voice/video.
3. Resolved the encryption-model branch directly from our own requirements rather than from
   scenario matching, using the discriminating question the pack supplies for that branch: *"Do
   other users need to decrypt the same ciphertext?"* Answer: yes, unambiguously.

### Final Solution

**Policy-governed VVK encryption**, with a **custom Forseti contract**. `VERIFIED` against
`canon/concepts.md` ("Self-Encryption vs Policy-Governed VVK Encryption") and
`canon/custom-contracts.md`.

Consequences accepted up front:

- We must write a C# Forseti contract and deploy it. There is no built-in contract that fits:
  `GenericRealmAccessThresholdRole` only validates *approvers*, not the *executor*, and its
  `ValidateData` is a no-op. We need executor validation (who is decrypting) plus
  direction-specific logic (encrypt rules differ from decrypt rules).
- Policy deployment requires a **human enclave approval in a browser**. It cannot be fully
  scripted. This is a hard constraint on the setup flow, not a limitation we can engineer around.
- We must call `IAMService.doEncrypt/doDecrypt` with policy bytes, **not** the
  `useTideCloak()` convenience wrappers, which silently omit the policy parameter and would give
  us self-encryption.

### What We Learned

1. **"Add encryption" is an under-specified request in Tide.** The first question is always "does
   anyone other than the author need to read this?", and it must be answered before any code is
   written, because the two answers lead to incompatible architectures.
2. **The convenience API is the trap.** `doEncrypt` exists on the `useTideCloak()` hook and looks
   like the natural thing to call. It is the *self*-encryption path. Shared encryption requires
   reaching past the hook to `IAMService` with policy bytes.
3. **Role names are documentation, not mechanism.** `_tide_<tag>.selfdecrypt` does not become
   shared decryption by being renamed. Mechanism lives in the call path.
4. Tide distinguishes **voucher gate roles** (`_tide_*`, which fund ORK operations) from
   **contract roles** (ordinary realm roles, which the Forseti contract checks). Using `_tide_*`
   roles for access control in a contract is anti-pattern AP-25. Our hospital roles must be plain
   realm roles.

### Important Implementation Decision

Architecture is set by this decision, before any code:

- **Frontend + backend:** Next.js 16 App Router, TypeScript. Single deployable. Chosen because
  Tide's Next.js path is the pack's best-supported and most-verified framework, and because
  encryption/decryption **must** happen in the browser — a server-side crypto layer would defeat
  the entire security property we are demonstrating.
- **Database:** SQLite via `better-sqlite3`. Chosen specifically for the demo: the "stolen
  database" scenario becomes "here is one file, read it", which is far more convincing than
  describing a hypothetical Postgres dump.
- **Encryption boundary:** the server is a **ciphertext store**. It never holds plaintext of
  alert bodies or patient report fields, and it has no decrypt path at all — not "has one but
  doesn't use it". This is what makes Scenario 13 (stolen database) and Scenario 14 (malicious
  admin) demonstrable rather than merely claimed.

### Pinned versions

`npm view` resolved the Tide SDK line to **0.14.20** at project start, and we pinned exactly that
across `@tidecloak/js`, `@tidecloak/nextjs`, `heimdall-tide`, and `asgard-tide`. Rationale: the
pack's version policy says all Tide packages are pre-1.0, must be pinned exactly, and must match
the TideCloak **server** version — a client/server mismatch stales `tide_dpop_auth.html`, which
fails login with an error that does not mention versions. We did not hardcode a version from
documentation; we resolved it from the registry. `VERIFIED`.

---

## 2026-09-10 — Bootstrap script language

### Task

Run the Tide bootstrap sequence (container → realm → licensing → IGA → users → adapter export).

### Issue

Every Tide playbook implements bootstrap as a bash script driving `curl` and `jq`. This machine is
Windows, and the only `bash` on `PATH` is `C:\WINDOWS\system32\bash.exe` — WSL's bash, which runs
in a different filesystem namespace. `jq` was present via WinGet; `curl` did not resolve as a real
executable in PowerShell (the name is taken by an `Invoke-WebRequest` alias).

### Cause

The Docker bind mount is the real problem, not the missing tools. The container needs
`-v <host-path>:/opt/keycloak/data/h2`. Under WSL bash, `$(pwd)` yields `/mnt/c/Users/...`, which
Docker Desktop resolves differently from the Windows path `C:\Users\...`. That class of mismatch
produces H2 permission and "could not open file" errors that look like Tide problems and are not.

### Attempted Solutions

1. Considered installing Git Bash and using that instead. Rejected: it introduces a dependency for
   no benefit and Git Bash has its own path-translation quirks with Docker volume arguments.
2. Considered translating paths inside the bash script. Rejected as fragile.

### Final Solution

Reimplemented the bootstrap in Node (`scripts/init-tidecloak.mjs` + `scripts/lib/tidecloak.mjs`).
Node was already a hard dependency, has native `fetch`, and resolves paths natively on Windows.

**The endpoint sequence and ordering are unchanged from the playbook.** This is an
implementation-language decision only. It is recorded here because a future reader comparing our
script to the Tide playbooks will find them structurally different and should know that was
deliberate rather than a drift.

### What We Learned

Rewriting the bootstrap turned out to be worth more than the portability. Two Tide behaviours are
much harder to get wrong in Node than in shell:

1. **A 2xx from an IGA-enabled admin endpoint means ACCEPTED, not APPLIED.** Role creation returns
   `202` and the role *does not exist* until its change request is committed. In shell this is easy
   to skip; expressing "mutate → drain → read back and assert" as a function makes it the default.
2. **The drain loop needs to authorize each change request individually.** `bulk-authorize` with
   `actionTypeIn: ["CREATE","DELETE"]` authorizes **zero** change requests and still returns `200`,
   because those are not real action-type values (the real ones are `CREATE_USER`, `GRANT_ROLES`,
   `UPDATE_PROTOCOL_MAPPER`, …). Omitting the filter returns `400`. A silent no-op that reports
   success is the worst available outcome, and we would probably have shipped it.

---

## 2026-09-10 — Realm import fails with an opaque 500

### Task

Create the `hospital` realm from our realm template.

### Issue

`POST /admin/realms` returned:

```
500 {"error":"unknown_error","error_description":"For more on this error consult the server log."}
```

No indication of what was wrong with the payload. The realm was not created.

### Cause

Found by reading the container log rather than guessing:

```
org.h2.jdbc.JdbcBatchUpdateException: Value too long for column
"DESCRIPTION CHARACTER VARYING(255)": "'VOUCHER GATE ONLY, not access control. ...(306)"
```

**Keycloak's `KEYCLOAK_ROLE.DESCRIPTION` column is `VARCHAR(255)`.** We had written long
explanatory descriptions on our realm roles — deliberately, because the distinction between
voucher-gate roles and Forseti-enforced roles is genuinely confusing and we wanted the explanation
visible in the admin console. Three of them exceeded 255 characters.

### Attempted Solutions

None wasted, because we read the log first. Recording that as the lesson: the 500 body says
"consult the server log", and it means it. `docker logs <container>` had the exact column, the exact
value, and the exact length.

### Final Solution

Shortened every role description to under 255 characters and moved the long-form explanation into
the contract source and the architecture doc, where there is no length limit. Added a check that
parses the template and asserts every description length before import.

### What We Learned

- This is a **stock Keycloak schema constraint**, not a Tide one. Worth internalising: TideCloak is
  Keycloak plus Tide extensions, so ordinary Keycloak limits still apply and will surface as
  generic 500s from the realm-import endpoint, which validates almost nothing up front.
- Realm import is close to all-or-nothing and reports failure without saying which of ~200 fields
  was at fault. Validating the template locally before POSTing is cheap and worth doing.
- We re-ran with `--wipe` rather than retrying in place. The Tide docs are firm that a partially
  initialised realm produces `REALM_SETUP_FAILED` on the next attempt, which is a *different and
  misleading* error that sends you chasing licensing instead of the original fault.

---

## 2026-09-10 — Confirmed: the `useTideCloak()` hook silently discards the encryption policy

### Task

Choose the API to call for policy-governed (shared) encryption.

### Issue

The obvious call is the one on the React hook:

```ts
const { doEncrypt, doDecrypt } = useTideCloak();
```

It is exported, it is typed, it is what every tutorial uses, and for this project it is **wrong**.

### Cause

Read out of the installed package rather than assumed —
`node_modules/@tidecloak/react/dist/esm/TideCloakContextProvider.js`:

```js
doEncrypt: async (data) => {
  ...
  const result = await IAMService.doEncrypt(data);      // ONE argument
  ...
},
doDecrypt: async (data) => {
  ...
  const result = await IAMService.doDecrypt(data);      // ONE argument
  ...
},
```

And the underlying method, from `@tidecloak/js/dist/cjs/src/IAMService.js`:

```js
async doEncrypt(data, decryption_policy = null) { ... }
async doDecrypt(data, decryption_policy = null) { ... }
```

The hook takes one parameter and the real method takes two. The policy defaults to `null`, so the
hook **always** performs self-encryption. There is no error, no warning, and no type complaint —
the hook's signature simply has nowhere to put a policy.

### Attempted Solutions

We did not have to debug this, because the Tide pack flagged it as an anti-pattern before we wrote
any code, and we checked the installed source to confirm it still held in 0.14.20. Recording the
verification because "the docs said so" and "the shipped code does so" are different strengths of
evidence, and this one is now the latter.

### Final Solution

Call `IAMService.doEncrypt(data, policyBytes)` / `IAMService.doDecrypt(data, policyBytes)` directly
from `src/lib/crypto-client.ts`, and never use the hook's crypto methods. The file carries a comment
saying so, with the reason, because the hook is what a future contributor will reach for.

We still use the hook for `secureFetch` and `getToken` — those must come from the hook, since the
static `IAMService` copies are not wired to the provider's auth state.

### What We Learned

1. **This is the single highest-consequence trap in the Tide SDK for an app like ours.** Everything
   would appear to work. The coordinator would encrypt an alert and read it back correctly. It would
   fail only when a *second* user tried to read, and the error would point at roles and policy
   rather than at the call site.
2. The failure is invisible to TypeScript. A one-argument function called with one argument
   typechecks perfectly.
3. General lesson we are carrying forward: for anything security-critical in this SDK, read the
   shipped `dist` rather than the README. Two of our findings so far (this and DPoP not being
   defaulted on) are cases where the installed code and the documentation disagree.

### Important Implementation Decision

`src/lib/crypto-client.ts` is the only module allowed to perform encryption or decryption. Nothing
else imports `IAMService` for crypto. Keeping it in one file means the policy argument can be
audited in one place instead of at every call site.

---

## 2026-09-10 — BLOCKED: `tide_dpop_auth.html` cannot be obtained, so DPoP is off

### Task

Enable DPoP token binding, which Tide states is the only recommended configuration and which our
realm template turns on server-side by default.

### Issue

DPoP requires four pieces on the client side, not one:

1. `useDPoP: { mode: 'strict', alg: 'ES256' }` inside the provider config
2. `public/tide_dpop_auth.html` — the relay page the Tide enclave loads to prove key possession
3. a wildcard rewrite `/tide_dpop/:path*` → `/tide_dpop_auth.html`
4. that path's own CSP plus `Allow-CSP-From: *`

We have 1, 3 and 4. **We cannot obtain 2.**

### Cause

The relay page is distributed by copy-paste, not by package:

- It is **not** in the `@tidecloak/*` npm packages. Verified: a recursive search of `node_modules`
  for `tide_dpop*` and for the string `tide_dpop` returns nothing at all.
- The SDK never references the path either, which is consistent — the *enclave* fetches the page
  from our origin, so grepping the SDK proves nothing about whether it is needed.
- The Tide MCP pack documents itself as the source of truth for this file and its `tide_dpop_asset`
  tool errors with: `tide_dpop_auth.html not found in any pack template`. The pack that says it is
  the only reliable source does not contain it.
- Not present in the public `tide-foundation` repositories we could reach. GitHub code search
  requires auth; direct raw URLs for the documented locations all 404.

### Attempted Solutions

1. `tide_dpop_asset` MCP tool — errors, file absent from the pack.
2. Recursive search of `node_modules` for the filename and for the string — nothing.
3. Five candidate raw.githubusercontent URLs across `tidecloak`, `tidecloak-gettingstarted`,
   `tidecloak-js` and `keylessh` — all 404.
4. GitHub API tree listing of `tide-foundation/tidecloak-gettingstarted` — no path matching `dpop`.
5. GitHub code search API — 401, needs a token.

### Final Solution

Disabled DPoP **in bidirectional lockstep**, which is the part that matters. Half-disabling it does
not degrade security, it breaks login outright:

- server on + client off → token endpoint returns `400 "DPoP proof is missing"`
- server off + client on → SDK init fails, the realm does not advertise DPoP support

So `scripts/set-dpop.mjs <on|off>` changes all three places together: the `dpop.bound.access.tokens`
attribute on the TideCloak client, `NEXT_PUBLIC_TIDE_DPOP` in `.env`, and thereby both the provider
config and the server-side `cnf.jkt` assertion. Ran it as `off`, verified the attribute committed.

Turning it back on is one command **plus** the file, and the script refuses to enable DPoP unless
`public/tide_dpop_auth.html` exists AND passes verification — because enabling it without the page
produces `TIDE-SWE-UNHANDLED`, an error that names neither DPoP nor a missing file.

The verification is worth keeping because two versions of this page circulate and the older one is
broken in a way that is nearly undiagnosable:

| sha256 | size | behaviour |
|---|---|---|
| `9d7844b938f0a2565fa910d3d30e9b8797cbfd6e0b73d59d804169a089aea757` | 9120 | good — posts to `window.opener \|\| window.parent` |
| `e725df1231f0050117de1a95948c3da3aca2757282ffdf65821940e668d95756` | 7183 | stale — posts only to `window.parent` |

`window.parent` is correct in an iframe and wrong in the popup fallback, where
`window.parent === window`, so the page messages itself and the opener never hears back.

### What We Learned

1. **A file distributed by copy-paste with no version marker is a supply-chain problem.** There is
   no way for an app to tell that its copy is stale, and the failure surfaces as a "failed to load"
   error for a page that returned HTTP 200 with a full body.
2. The dependency is invisible from our side of the wire. Nothing in the SDK requests this path, so
   ordinary code archaeology cannot discover the requirement.
3. Disabling a bidirectional security control is not a one-line change, and treating it as one is
   how you get a broken login instead of a weaker one.

### Important Implementation Decision

**This is the project's one known security gap, and we are not hiding it.** With DPoP off, access
tokens are plain bearer tokens: a token captured from a log, a proxy, or browser storage can be
replayed from another device. That is finding SG-03, severity HIGH.

It is worth being precise about what this does and does not affect, because it would be easy to
either overstate or understate it:

- It **does** weaken authentication — token theft becomes replayable.
- It does **not** affect the demonstrations that are the point of this project. Alert and report
  confidentiality rests on the Forseti contract and the ORK threshold, not on how the access token
  is bound. A stolen bearer token belonging to `doctor-b` still cannot decrypt patient 1's reports,
  and a stolen token belonging to `hospital-admin` still cannot decrypt anything, because the ORKs
  check the roles in the doken.
- The stolen-database and malicious-administrator scenarios are entirely unaffected.

Recorded in `docs/SECURITY-GAPS.md` with the exact steps to close it. Status: `UNRESOLVED`,
pending the file from the Tide team.

---

## Open questions carried forward

| # | Question | Status |
|---|---|---|
| Q-1 | Can the Forseti policy deployment be automated at all, or is the browser enclave approval strictly unavoidable for a one-time setup? | `UNRESOLVED` — pack says a human approval is required; to be confirmed by observation |
| Q-2 | Does the enclave approval card render for our `ApprovalType`? The pack marks the `BasicCustom<Custom<X>>` double-wrap as PREDICTED, not network-verified. | `UNRESOLVED` |
| Q-3 | How long does role propagation actually take after an IGA commit? Pack says "up to 120s". | `UNRESOLVED` |
