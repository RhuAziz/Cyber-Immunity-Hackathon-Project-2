# Hospital Emergency Platform

A small Next.js hospital emergency alerting and incident-reporting proof of concept. It addresses a common security problem in sensitive clinical workflows: an application server or database administrator may be able to read database rows and change application ACLs, but that alone should not reveal encrypted alert or patient-report content.

The browser encrypts sensitive content before it reaches the application. The app stores ciphertext in a local SQLite database, while Tide enforces the cryptographic access decision outside that database.

## How Tide fits

- **TideCloak** provides the OIDC login flow, Tide identities, realm roles, authenticated sessions, and IGA-governed administration.
- **Forseti** is the C# access contract in `forseti/HospitalAccessPolicy.cs`. It runs in the ORK network and checks the caller before encryption/decryption. It supports team tags such as `hosp:careteam-patient-1` and identity tags such as `hosp:user:<vuid>`.
- **The Tide ORK network** independently evaluates the contract and performs threshold-backed encryption/decryption. The Next.js server never decrypts alert or report content.
- **The application/API and SQLite** provide the UI, route-level JWT/role checks, recipient/care-team filtering, ciphertext storage, and audit records. Database ACLs are not the cryptographic authority.

## Requirements

Install:

- Git
- Node.js and npm
- Docker Desktop
- A browser with pop-ups allowed for the Tide enclave

This guide assumes Windows PowerShell and the project directory:

```powershell
C:\Users\nadia\Tidecloack app
```

## Setup

Run these steps in order from the project directory.

### 1. Clone, install dependencies, and configure secrets

Clone this repository using its repository URL, then open the project directory:

```powershell
git clone <repository-url>
cd "Tidecloack app"
npm install
Copy-Item .env.example .env
```

Edit `.env` and set a real value for `KC_BOOTSTRAP_ADMIN_PASSWORD`. Before running `npm run init`, check that the app origin matches the port used by `npm run dev`:

```text
CLIENT_APP_URL=http://localhost:3100
```

If the realm was already initialized with the wrong origin, run:

```powershell
node scripts/set-app-origin.mjs http://localhost:3100
```

This updates the registered redirect/web origin, re-signs the Tide IdP settings, and refreshes the adapter. In MultiAdmin mode, the resulting change requests may require approval in the TideCloak Change Requests view. Approve them one at a time and wait for each request to commit before approving the next; approving them together can make later commits fail with a quorum signature hash mismatch.

Do not commit `.env`.

### 2. Start TideCloak

The bootstrap script starts and configures the required container automatically:

```powershell
npm run init
```

It uses the image `tideorg/tidecloak-dev:latest`, exposes TideCloak at `http://localhost:8080`, creates the `hospital` realm and `hospital-app` client, enables Tide/IGA, creates the demo roles and users, generates enrollment links, and exports `data/tidecloak.json`.

The underlying Docker command is:

```powershell
docker run -d --name tidecloak-hospital `
  -v "C:\Users\nadia\Tidecloack app\tidecloak\h2:/opt/keycloak/data/h2" `
  -p 8080:8080 `
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin `
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="<same-password-as-.env>" `
  tideorg/tidecloak-dev:latest
```

Use `npm run init` for a complete bootstrap rather than running only this Docker command.

### 3. Enrol the demo users

Open the links in:

```text
tidecloak\enrollment-links.md
```

Enrol `hospital-admin` first, then `coordinator`, `nurse-a`, `doctor-a`, and `doctor-b`. Tide creates the user credential in the browser; there are no seeded application passwords. The links expire after 12 hours. Regenerate them with:

```powershell
node scripts/invite-links.mjs
```

A created username is not the same as a completed Tide enrollment. The user must have a linked Tide identity before proceeding.

### 4. Finalize the realm

After `hospital-admin` has completed Tide enrollment:

```powershell
npm run finalize
```

This completes the administrator role/policy prerequisite. Refresh or sign in again after role changes so the current roles reach the Tide session.

### 5. Run the app and deploy the policy

Start the app:

```powershell
npm run dev
```

Open:

```text
http://localhost:3100
```

Sign in as `hospital-admin`, then open:

```text
http://localhost:3100/setup
```

Choose **Deploy policy** and approve the request in the Tide enclave popup. All nine setup steps must complete before encryption and decryption are available. The signed policy is stored in SQLite, but its cryptographic authority comes from Tide/ORK threshold signing.

## Test accounts and access

All accounts are created by `npm run init` and enrolled through their invitation links. The role-tag access below applies to existing team-tagged alerts and patient reports.

| Account | Roles/access | Expected use |
|---|---|---|
| `coordinator` | `coordinator`, `clinical-staff`, `response-team-infection-control` | Raises alerts, encrypts, and decrypts response-team alerts; can delete alerts it raised. |
| `nurse-a` | `nurse`, `emergency-responder`, `clinical-staff`, `response-team-infection-control`, `careteam-patient-1` | Decrypts response-team alerts, creates patients, files reports, and decrypts patient 1 reports. |
| `doctor-a` | `doctor`, `emergency-responder`, `clinical-staff`, `response-team-infection-control`, `careteam-patient-1` | Decrypts response-team alerts and patient 1 reports; can file reports. |
| `doctor-b` | `doctor`, `emergency-responder`, `clinical-staff`; no tag roles | Can encrypt/file where the app allows it, but is refused for role-tagged response-team alerts and patient reports. If selected in Named individual mode, the identity tag can authorize this clinical user specifically. |
| `hospital-admin` | `hospital-admin`; no `clinical-staff` or tag roles | Deploys the policy and administers the application/database, but cannot encrypt or decrypt protected content under the Forseti contract. |

Named individual mode on `/alerts/new` selects one enrolled user and creates a tag in this format:

```text
hosp:user:<vuid>
```

The identity-tag contract requires the matching Tide VUID and the `clinical-staff` role. Team mode continues to use role tags such as `hosp:response-team-infection-control`.

## Demo and verification

After policy deployment, verify both the happy paths and the denials in separate browser sessions:

1. Sign in as `coordinator` and open `/alerts/new`.
2. Use a team mode to raise an alert. Confirm the body is encrypted in the browser and stored as ciphertext.
3. Decrypt the alert as `coordinator` or `doctor-a`.
4. Put `doctor-b` on the application recipient list and confirm the ORK network still refuses decryption because the required response-team role is absent.
5. Use **Named individual** mode to select one enrolled clinical user. Confirm the tag is `hosp:user:<vuid>` and that the selected user can decrypt after the contract/policy is deployed.
6. Sign in as `nurse-a` and open `/reports/new`. Create the patient record and file a report tagged `hosp:careteam-patient-1`.
7. Decrypt the report as `doctor-a`.
8. Confirm `hospital-admin` is refused for both alerts and reports.

The API also enforces authentication and route roles server-side; hidden buttons are only UI convenience.

### Attack 1: stolen database

After creating an alert and report, run:

```powershell
npm run attack:steal-db
```

This opens `data/hospital.db` offline and prints its tables and rows. Expected result:

- Alert, patient, and report payloads are ciphertext.
- Grepping the raw output for clinical content, ward, and severity terms produces no plaintext matches.
- Metadata remains readable, including IDs, timestamps, tags, authors, recipient lists, and care-team membership.

### Attack 2: malicious database administrator

Run:

```powershell
npm run attack:admin-escalate
```

Expected result:

- The SQL insert adding `hospital-admin` to the `care_team` table succeeds at the application layer.
- The patient page shows the application care team as authorised.
- The ORK network still refuses decryption because the administrator lacks the required Tide role.
- The script can be reverted with:

```powershell
npm run attack:admin-escalate -- --revert
```

The administrator can still alter ACLs, delete records, deny service, and read database metadata. The demonstration only claims that the database edit cannot produce protected plaintext.

## Chrome localhost issue

Chrome can block the Tide enclave when it tries to reach a local TideCloak service, even though `http://localhost:8080` returns HTTP 200 in PowerShell or another tool. The SDK may then report `TIDE-TIDEJS-NET-FETCH_FAILED`; this is commonly a browser origin/CORS or Chrome local-network permission problem.

Use the exact application origin:

```text
http://localhost:3100
```

Do not mix it with `http://127.0.0.1:3100`. In Chrome, allow pop-ups and allow **Local network access** for the application when prompted (or in the site permissions). If Chrome still blocks the enclave, use Microsoft Edge or Firefox for the setup/policy-approval flow. The registered origin and the URL in the browser must match exactly.

## Known limitations

- **DPoP is disabled.** The required `tide_dpop_auth.html` relay asset is not available in Tide's published `@tidecloak/*` packages, so DPoP remains off in lockstep rather than being partially enabled. Access tokens are therefore bearer tokens and can be replayed if stolen.
- **The project is a local proof of concept.** It uses SQLite, local TideCloak Docker state, local HTTP URLs, and development configuration. Use HTTPS, proper secret storage, backups, and hardened infrastructure before treating it as a production system.
- **Database metadata is not encrypted.** Ciphertext protects alert/report content, but usernames, recipient lists, care-team membership, tags, IDs, and timestamps remain visible to a database reader.
- **Application ACLs are not cryptographic authority.** A database administrator can change recipient/care-team rows or delete data. The Forseti/ORK decision is what prevents that edit from granting decryption.
- **Tide enrollment and policy deployment require browser interaction.** Enrollment links expire, and policy signing requires human approval in the Tide enclave.
- **A policy/contract source change requires redeployment.** The policy is bound to the exact contract identity; do not edit the Forseti contract and assume the old signed policy covers it.
- **The client uses bootstrap admin credentials for some local TideCloak admin REST calls.** This is acceptable for the PoC setup but should be replaced with least-privilege short-lived administration before production.
- **Online Tide access is required for cryptographic operations.** The application has no offline decrypt fallback.

## Useful commands

```powershell
npm run diagnose       # inspect realm state; avoid using it as a mutation-free check
npm run invite         # regenerate enrollment links
npm run finalize       # complete post-enrollment setup
npm run build          # production build
npm run typecheck      # TypeScript check
```
