# Hospital Emergency Platform User Flow

This flow describes the implemented PoC, based on the routes and client code in `src/app` and `src/lib`. The primary journey starts at `/` and ends when an authorised care-team user decrypts the patient record and report at `/patients/patient-1`.

## Start, end, and prerequisite

- **Start:** An enrolled hospital user opens `/` and selects **Sign in with Tide**.
- **Administrator prerequisite:** Before encryption is available, a `hospital-admin` opens `/setup`, uploads the Forseti contract, approves the request in the Tide enclave, and waits for the ORK threshold signature. The signed policy is then stored through `/api/policy`.
- **Core end:** A clinical user files an encrypted incident report and opens `/patients/patient-1`, where the authorised care team can decrypt the patient and report data. A user without the required Tide role reaches the same page but receives an ORK decryption denial.

## Implemented flow

```mermaid
flowchart TD
    A[Open /] --> B[Select Sign in with Tide]
    B --> C[TideCloak OIDC login]
    C --> D[/auth/redirect exchanges code]
    D --> E[/dashboard]

    P[Hospital-admin opens /setup] --> P1[Upload Forseti contract]
    P1 --> P2[Fetch admin policy and build Tide request]
    P2 --> P3[Approve in Tide enclave]
    P3 --> P4[ORK threshold signature]
    P4 --> P5[Store signed policy in /api/policy]
    P5 --> E

    E --> F[Coordinator opens /alerts/new]
    F --> G[Enter alert and choose response team/recipients]
    G --> H[Browser encrypts with IAMService + signed policy]
    H --> I[POST /api/alerts stores ciphertext and ACL]
    I --> J[Dashboard lists protected alert]
    J --> K[User selects Decrypt]
    K --> L{ORK/Forseti checks tag role}
    L -->|Allowed| M[Alert plaintext shown]
    L -->|Denied| N[Access denied shown]

    M --> O[/reports/new?alertId=...]
    O --> Q[Clinical user enters patient and report details]
    Q --> R[Browser encrypts patient and report]
    R --> S[POST /api/patients and /api/reports]
    S --> T[Open /patients/patient-1]
    T --> U[Select Decrypt]
    U --> V{ORK/Forseti checks care-team role}
    V -->|Allowed| W[Patient and report plaintext shown]
    V -->|Denied| X[Access denied shown]
```

## Steps and Tide/TideCloak involvement

1. **Authenticate.** The user starts at `/` (`src/app/page.tsx`) and chooses Tide login. `TideCloakProvider` manages the OIDC flow. `/auth/redirect` completes the code exchange and redirects to `/dashboard`. Authenticated API requests use TideCloak `secureFetch`.
2. **Load the policy.** Protected pages call `GET /api/policy` through `secureFetch`. The browser caches the signed policy bytes. If no policy exists, the UI directs the user to `/setup` and disables encryption/decryption.
3. **Deploy the policy when required.** The administrator setup page uploads `HospitalAccessPolicy.cs`, creates the policy request, obtains human enclave approval, and asks the ORK network for a threshold signature. The resulting signed policy is stored in SQLite through `/api/policy`. TideCloak supplies the administrator identity and `tide-realm-admin` policy used by this setup flow.
4. **Raise an alert.** A user with the `coordinator` realm role opens `/alerts/new`. The browser encrypts the complete form using `IAMService.doEncrypt` and a tag such as `hosp:response-team-infection-control`. The Forseti contract requires the Tide identity to have `clinical-staff`. The API verifies the JWT and coordinator role, then stores only the ciphertext, tag, and recipient ACL.
5. **Read the alert.** `/dashboard` loads visible alert envelopes from `GET /api/alerts`. When the user clicks **Decrypt**, the browser sends the envelope, tag, and signed policy to Tide's ORK network. Forseti derives the required realm role from the tag. The plaintext is shown only if the Tide session has that role; otherwise the UI reports an ORK denial. Decrypt outcomes are reported best-effort to `/api/audit`.
6. **File the report.** From a decrypted alert, a nurse or doctor opens `/reports/new?alertId=...`. The browser encrypts the patient identity and clinical report under `hosp:careteam-patient-1`, then sends the envelopes to `/api/patients` and `/api/reports`. The API verifies the Tide JWT and clinical role and stores ciphertext only.
7. **Complete the PoC.** The user opens `/patients/patient-1`, loads the report envelopes, and selects **Decrypt**. Tide's ORKs and the Forseti contract require the `careteam-patient-1` realm role. An authorised care-team user sees the patient/report data; another user can see an application-level record but cannot obtain plaintext when the ORKs deny the request.

At no point does the Next.js server decrypt protected content. TideCloak supplies identity and roles, while Tide's browser SDK and ORK network perform the policy-governed encryption and decryption.
