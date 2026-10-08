# Hospital Emergency Platform

A small Next.js hospital emergency alerting and incident-reporting PoC. TideCloak provides login and roles; Tide policy-governed encryption keeps alert and patient-report content encrypted before it reaches the application database. Forseti runs the access rules across the Tide ORK network. The app stores ciphertext, application metadata, and ACLs in SQLite.

## Requirements

Install:

- Node.js and npm
- Docker Desktop
- A browser with pop-ups allowed for the Tide enclave

This guide assumes Windows PowerShell and the project directory:

```powershell
C:\Users\nadia\Tidecloack app
```

## Setup

Run these steps in order from the project directory.

### 1. Install dependencies and configure secrets

```powershell
npm install
Copy-Item .env.example .env
```

Edit `.env` and set a real value for `KC_BOOTSTRAP_ADMIN_PASSWORD`. Use port `3100` for this project:

```text
CLIENT_APP_URL=http://localhost:3100
```

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

Enrol `hospital-admin` first, then `coordinator`, `nurse-a`, `doctor-a`, and `doctor-b`. The links expire after 12 hours. Regenerate them with:

```powershell
node scripts/invite-links.mjs
```

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

Choose **Deploy policy** and approve the request in the Tide enclave popup. All nine setup steps must complete before encryption and decryption are available.

## Demo flow

- Sign in as `coordinator` and raise an alert from `/alerts/new`.
- Decrypt it as an authorised response-team user.
- Use `/reports/new` to file an encrypted patient incident report.
- Open `/patients/patient-1` as an authorised care-team user and decrypt the report.
- `doctor-b` and `hospital-admin` should be refused by the ORK network for protected content.
- Run the attack demonstrations after creating data:

```powershell
npm run attack:steal-db
npm run attack:admin-escalate
```

## Chrome localhost issue

Chrome can block the Tide enclave when it tries to reach a local TideCloak service, even though `http://localhost:8080` returns HTTP 200 in PowerShell or another tool. The SDK may then report `TIDE-TIDEJS-NET-FETCH_FAILED`; this is commonly a browser origin/CORS or Chrome local-network permission problem.

Use the exact application origin:

```text
http://localhost:3100
```

Do not mix it with `http://127.0.0.1:3100`. In Chrome, allow pop-ups and allow **Local network access** for the application when prompted (or in the site permissions). If Chrome still blocks the enclave, use Microsoft Edge or Firefox for the setup/policy-approval flow. The registered origin and the URL in the browser must match exactly.

## Useful commands

```powershell
npm run diagnose       # inspect realm state; avoid using it as a mutation-free check
npm run invite         # regenerate enrollment links
npm run finalize       # complete post-enrollment setup
npm run build          # production build
npm run typecheck      # TypeScript check
```
