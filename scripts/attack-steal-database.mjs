/**
 * ATTACK DEMONSTRATION 1 — Stolen database
 *
 * Plays the part of an attacker who has exfiltrated the application database and is now reading it
 * offline, with no application, no network, and no credentials. Exactly what a real breach looks
 * like: someone has the file.
 *
 *     npm run attack:steal-db
 *
 * This script does nothing clever. It opens data/hospital.db and prints every row of every table,
 * which is the strongest possible version of the attack — there is no filtering to accuse us of.
 */

import Database from "better-sqlite3";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { PROJECT_ROOT } from "./lib/tidecloak.mjs";

const DB = resolve(PROJECT_ROOT, "data", "hospital.db");

const line = (c = "-") => console.log(c.repeat(78));

console.log();
line("=");
console.log("  ATTACK 1: THE DATABASE HAS BEEN STOLEN");
line("=");
console.log(`
  Scenario: an attacker has a copy of the application database. No app, no
  network, no login. They are reading the file directly, which is what a real
  exfiltration gives you.

  Target: ${DB}
`);

if (!existsSync(DB)) {
  console.log("  The database does not exist yet.");
  console.log("  Sign in, raise an alert and file a report first, then re-run.\n");
  process.exit(0);
}

const db = new Database(DB, { readonly: true });

/* ---------------- what an attacker sees first ---------------- */
const tables = db
  .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
  .all()
  .map((r) => r.name);

console.log(`  Tables found: ${tables.join(", ")}\n`);

/* ---------------- the prize: patient reports ---------------- */
line();
console.log("  TARGET 1: incident reports (patient names, conditions, medication)");
line();

const reports = db.prepare("SELECT * FROM reports").all();
if (reports.length === 0) {
  console.log("  (none filed yet)\n");
} else {
  for (const r of reports) {
    console.log(`
  report id   : ${r.id}
  patient id  : ${r.patient_id}
  filed by    : ${r.filed_by}
  filed at    : ${r.created_at}
  tag         : ${r.tag}

  payload_ciphertext (this is the whole clinical record):
`);
    const c = r.payload_ciphertext;
    for (let i = 0; i < Math.min(c.length, 480); i += 78) {
      console.log(`    ${c.slice(i, i + 78)}`);
    }
    if (c.length > 480) console.log(`    … ${c.length - 480} more characters`);
    console.log(`\n  total ciphertext length: ${c.length} characters`);

    // Show that the obvious things to grep for simply are not there.
    const probes = [
      "John", "Smith", "fever", "breathing", "Medication", "Ward",
      "condition", "symptom", "oxygen", "isolat",
    ];
    const hits = probes.filter((p) => c.toLowerCase().includes(p.toLowerCase()));
    console.log(
      `  grep for ${probes.length} obvious clinical terms: ${
        hits.length === 0 ? "0 hits" : `HITS: ${hits.join(", ")}`
      }`
    );
  }
  console.log();
}

/* ---------------- alerts ---------------- */
line();
console.log("  TARGET 2: emergency alerts (which ward, how bad, before disclosure)");
line();

const alerts = db.prepare("SELECT * FROM alerts").all();
if (alerts.length === 0) {
  console.log("  (none raised yet)\n");
} else {
  for (const a of alerts) {
    console.log(`
  alert id    : ${a.id}
  raised by   : ${a.created_by}
  raised at   : ${a.created_at}
  tag         : ${a.tag}
  ciphertext  : ${a.payload_ciphertext.slice(0, 120)}…  (${a.payload_ciphertext.length} chars)`);
    const probes = ["Ward 7", "outbreak", "infectious", "High", "Critical"];
    const hits = probes.filter((p) => a.payload_ciphertext.toLowerCase().includes(p.toLowerCase()));
    console.log(`  grep for ward/severity terms: ${hits.length === 0 ? "0 hits" : `HITS: ${hits.join(", ")}`}`);
  }
  console.log();
}

/* ---------------- patients ---------------- */
line();
console.log("  TARGET 3: patient identities");
line();
const patients = db.prepare("SELECT * FROM patients").all();
if (patients.length === 0) {
  console.log("  (none)\n");
} else {
  for (const p of patients) {
    console.log(`
  record id   : ${p.id}       <- an opaque handle, not a name
  tag         : ${p.tag}
  ciphertext  : ${p.payload_ciphertext.slice(0, 120)}…  (${p.payload_ciphertext.length} chars)`);
  }
  console.log(`
  Note: even the patient's NAME is inside the envelope. For a high-profile
  patient the identity is the secret worth stealing, so a readable name column
  would have lost the game before any medical detail was involved.
`);
}

/* ---------------- what IS readable: be honest about it ---------------- */
line();
console.log("  WHAT THE ATTACKER *DOES* GET — stated plainly, not glossed over");
line();

const recips = db.prepare("SELECT alert_id, username FROM alert_recipients ORDER BY alert_id").all();
const team = db.prepare("SELECT patient_id, username FROM care_team ORDER BY patient_id").all();

console.log(`
  This design does NOT hide everything, and pretending otherwise would be
  dishonest. Readable metadata:

   - alert recipients (${recips.length} row(s)):`);
for (const r of recips) console.log(`       alert ${r.alert_id.slice(0, 8)}… -> ${r.username}`);

console.log(`
   - care team membership (${team.length} row(s)):`);
for (const t of team) console.log(`       ${t.patient_id} -> ${t.username}`);

console.log(`
   - who raised what and when, and the tag on each record.

  Why this matters, per requirements section 8: seeing that a cluster of
  infection-control staff was suddenly assigned to one ward lets an attacker
  INFER a serious incident there, without reading a single word of content.
  That is a real residual disclosure and it is recorded as a known gap in
  docs/SECURITY-GAPS.md rather than being claimed as solved.

  The server needs these columns to answer "which alerts may this user list",
  so they cannot be ciphertext without giving the server a decrypt path — which
  would defeat the far more important property below.
`);

line("=");
console.log("  RESULT");
line("=");
console.log(`
  Readable   : structure, timing, and who-was-involved metadata.
  NOT readable: every alert body, every patient name, every condition,
                medication, observation, test result and action taken.

  Crucially, the attacker cannot make progress from here. The ciphertext keys
  do not exist in this file, and they do not exist in the application either.
  They never exist in whole form anywhere: decryption requires a threshold of
  independent ORK nodes to cooperate, and each one first checks the requesting
  user's roles against our Forseti contract.

  So there is nothing to crack offline. An attacker holding this file forever
  gets no closer.
`);

db.close();
