/**
 * ATTACK DEMONSTRATION 2 — Malicious administrator escalating via the database
 *
 * This is the project's headline demonstration.
 *
 *     npm run attack:admin-escalate
 *
 * The administrator has full write access to the application database. They are not on any
 * patient's care team. They add themselves — a single INSERT — and the application now sincerely
 * believes they are authorised.
 *
 * The script performs the escalation for real, proves the application's view changed, and then
 * shows why it buys them nothing.
 *
 * Pass --revert to undo it.
 */

import Database from "better-sqlite3";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { PROJECT_ROOT, loadEnv, adminFetch, findUser } from "./lib/tidecloak.mjs";

const DB = resolve(PROJECT_ROOT, "data", "hospital.db");
const ATTACKER = "hospital-admin";
const PATIENT = "patient-1";
const REQUIRED_ROLE = "careteam-patient-1";

const line = (c = "-") => console.log(c.repeat(78));

console.log();
line("=");
console.log("  ATTACK 2: THE ADMINISTRATOR REWRITES THE CARE TEAM");
line("=");

if (!existsSync(DB)) {
  console.log(`
  The database does not exist yet. Run the demo flow first:
    1. coordinator raises an alert
    2. nurse-a files an incident report for ${PATIENT}
  Then re-run this script.
`);
  process.exit(0);
}

const db = new Database(DB);
const revert = process.argv.includes("--revert");

if (revert) {
  const r = db
    .prepare("DELETE FROM care_team WHERE patient_id = ? AND username = ?")
    .run(PATIENT, ATTACKER);
  console.log(`\n  Reverted: removed ${r.changes} row(s). ${ATTACKER} is off the care team again.\n`);
  db.close();
  process.exit(0);
}

/* ---------------- 1. before ---------------- */
line();
console.log("  STEP 1 — Before the attack");
line();

const before = db.prepare("SELECT username FROM care_team WHERE patient_id = ? ORDER BY username").all(PATIENT);
console.log(`\n  Application care team for ${PATIENT}:`);
if (before.length === 0) console.log("    (empty — file a report first so the patient record exists)");
for (const m of before) console.log(`    - ${m.username}`);
console.log(`\n  ${ATTACKER} present: ${before.some((m) => m.username === ATTACKER) ? "yes" : "no"}`);

const reports = db.prepare("SELECT * FROM reports WHERE patient_id = ?").all(PATIENT);
console.log(`  Encrypted reports for this patient: ${reports.length}`);

if (reports.length === 0) {
  console.log(`
  There is nothing to attempt reading. File a report as nurse-a first.
`);
  db.close();
  process.exit(0);
}

/* ---------------- 2. the escalation ---------------- */
line();
console.log("  STEP 2 — The escalation (a single INSERT, as the DB owner)");
line();
console.log(`
  SQL executed:

    INSERT INTO care_team (patient_id, username, added_at)
    VALUES ('${PATIENT}', '${ATTACKER}', datetime('now'));
`);

db.prepare("INSERT OR IGNORE INTO care_team (patient_id, username, added_at) VALUES (?, ?, ?)").run(
  PATIENT,
  ATTACKER,
  new Date().toISOString()
);

const after = db.prepare("SELECT username FROM care_team WHERE patient_id = ? ORDER BY username").all(PATIENT);
console.log(`  Application care team for ${PATIENT} is now:`);
for (const m of after) console.log(`    - ${m.username}${m.username === ATTACKER ? "   <-- INSERTED BY THE ATTACKER" : ""}`);

console.log(`
  The attack SUCCEEDED at the application layer. This is not a simulation and
  nothing rejected it: the application's own access-control table now lists the
  administrator as an authorised member of this patient's care team. Any check
  written against this table will pass.
`);

/* ---------------- 3. what did NOT change ---------------- */
line();
console.log("  STEP 3 — What the administrator did NOT gain");
line();

const cfg = loadEnv();
let roleNames = [];
let enrolled = false;

try {
  const user = await findUser(cfg, ATTACKER);
  if (user) {
    enrolled = !!user.attributes?.tideUserKey?.[0];
    const rm = await adminFetch(cfg, `/admin/realms/${cfg.realm}/users/${user.id}/role-mappings/realm/composite`);
    roleNames = (rm.body || []).map((r) => r.name).sort();
  }
} catch (err) {
  console.log(`  (could not reach TideCloak to read roles: ${err.message})`);
}

console.log(`
  Realm roles actually held by ${ATTACKER}, according to TideCloak:

    ${roleNames.length ? roleNames.join("\n    ") : "(unavailable)"}

  Tide enrolled: ${enrolled ? "yes" : "no"}

  The role the ORK network requires to decrypt these reports:

    ${REQUIRED_ROLE}      <-- ${roleNames.includes(REQUIRED_ROLE) ? "PRESENT" : "ABSENT"}
`);

const sample = reports[0];
console.log(`  The ciphertext is tagged "${sample.tag}". Our Forseti contract strips the`);
console.log(`  "hosp:" namespace and demands the remainder — "${REQUIRED_ROLE}" — as a`);
console.log(`  realm role in the caller's session token, on EVERY ORK, independently.\n`);

/* ---------------- 4. why the DB edit cannot help ---------------- */
line();
console.log("  STEP 4 — Why editing the database cannot fix that");
line();
console.log(`
  The administrator's obvious next move is to grant themselves the role. They
  cannot do it from here, for a structural reason rather than a policy one:

  1. The role does not live in this database. It lives in TideCloak, and it is
     the session token — not our care_team table — that the ORKs read.

  2. Granting a realm role is an IGA-governed change. It becomes a change
     request that needs quorum approval, sealed by a threshold signature from
     the ORK network. This realm runs IGA in Tide mode (iga.attestor=tide), so
     the approval is cryptographic, not a workflow flag someone can flip.

  3. Once the realm went multiAdmin, even a full-power admin token cannot
     approve its own change request. TideCloak answers:

       409 MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE

     The approval has to be signed by a human in the enclave. A stolen admin
     credential is not enough.

  4. Forging a token with the role in it does not work either. TideCloak does
     not sign tokens by itself — signing is a threshold operation across the
     ORKs, each of which independently verifies the claims before contributing
     a partial signature. Compromising the TideCloak server outright still does
     not produce a token that our JWT verification accepts, because that
     verification uses the embedded vendor key from the adapter, not a key
     fetched from the server being attacked.
`);

/* ---------------- 5. verify it ---------------- */
line();
console.log("  STEP 5 — See it for yourself");
line();
console.log(`
  The database now says the administrator is authorised. Go and use it:

    1. npm run dev
    2. sign in as ${ATTACKER}
    3. open http://localhost:3000/patients/${PATIENT}
    4. the page will show:
         Application care team ......... authorised     <- the attack worked
         ORK network ................... refuses        <- and it did not matter
    5. press Decrypt and read the refusal from the ORK network

  Undo the escalation with:
    npm run attack:admin-escalate -- --revert
`);

line("=");
console.log("  RESULT");
line("=");
console.log(`
  Application-side permission manipulation SUCCEEDED.
  Access to the protected information DID NOT FOLLOW.

  That gap is the whole point. In a conventional design these two are the same
  thing, because the application both decides authorisation and holds the data.
  Here the authorisation decision is made by a threshold of independent nodes
  reading a token the application cannot mint, against a contract the
  application cannot edit.

  The honest converse, so the claim is not overstated: an administrator who can
  write to this database CAN still do plenty of damage — delete records, alter
  recipient lists, deny service, and read the metadata described in
  docs/SECURITY-GAPS.md. What they cannot do is read the clinical content.
`);

db.close();
