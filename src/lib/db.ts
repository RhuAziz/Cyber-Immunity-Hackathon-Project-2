import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

/**
 * SQLite is deliberate. The "stolen database" demonstration becomes "here is one file, open it",
 * which is far more convincing than describing a hypothetical Postgres dump.
 *
 * WHAT IS IN HERE, AND WHAT IS NOT
 *
 * Ciphertext columns (`payload_ciphertext`) hold TideMemory envelopes produced in the browser by
 * the ORK network under our Forseti policy. This process has no key material and no decrypt path.
 * There is no "decrypt on the server" function to accidentally call, because writing one would
 * void the whole security property.
 *
 * Plaintext columns are an index, and they are an HONEST LIMITATION rather than an oversight:
 *
 *   - alert.created_by, alert_recipients.username, care_team.username
 *     The server needs these to enforce the application ACL, so they cannot be ciphertext.
 *     Consequence: an attacker with this file learns WHO was alerted and WHO is on a care team.
 *     Per requirements section 8 that is itself sensitive — it can reveal that a large number of
 *     specialists were suddenly assigned to one ward. We do not claim to protect it.
 *     What the attacker still cannot do is read any alert or report CONTENT.
 *
 *   - the `tag` column
 *     Names the realm role the ORKs will demand before decrypting. Knowing the tag does not help:
 *     an attacker who names a tag still needs a doken carrying that role, and roles are
 *     IGA-governed. Storing it in the clear is safe and necessary to build the decrypt request.
 *
 * No titles, descriptions, wards, severities, patient names, conditions, medications or
 * observations are stored in plaintext anywhere.
 */

const DB_PATH = resolve(process.cwd(), "data", "hospital.db");

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (db) return db;

  mkdirSync(resolve(process.cwd(), "data"), { recursive: true });
  db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migrate(db);
  return db;
}

function migrate(d: Database.Database) {
  d.exec(`
    CREATE TABLE IF NOT EXISTS patients (
      id                 TEXT PRIMARY KEY,
      -- The patient's own identity is sensitive (requirements section 9, high-profile patient),
      -- so even the name is a ciphertext envelope, not a column we can read.
      payload_ciphertext TEXT NOT NULL,
      tag                TEXT NOT NULL,
      created_at         TEXT NOT NULL
    );

    -- The application ACL. This is the table a malicious administrator edits in the attack demo:
    -- adding a row here makes the APPLICATION believe they are authorised, and changes nothing
    -- about whether the ORK network will decrypt for them.
    CREATE TABLE IF NOT EXISTS care_team (
      patient_id TEXT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      username   TEXT NOT NULL,
      added_at   TEXT NOT NULL,
      PRIMARY KEY (patient_id, username)
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id                 TEXT PRIMARY KEY,
      created_by         TEXT NOT NULL,
      created_at         TEXT NOT NULL,
      -- Names the realm role the ORKs require to decrypt this alert.
      tag                TEXT NOT NULL,
      -- title, description, ward, emergency type, severity — all inside here, all encrypted.
      payload_ciphertext TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alert_recipients (
      alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
      username TEXT NOT NULL,
      PRIMARY KEY (alert_id, username)
    );

    CREATE TABLE IF NOT EXISTS reports (
      id                 TEXT PRIMARY KEY,
      alert_id           TEXT REFERENCES alerts(id) ON DELETE SET NULL,
      patient_id         TEXT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
      filed_by           TEXT NOT NULL,
      created_at         TEXT NOT NULL,
      tag                TEXT NOT NULL,
      -- patient condition, symptoms, medication, observations, test results, location, actions.
      payload_ciphertext TEXT NOT NULL
    );

    -- Signed Forseti policy bytes, base64. Not a secret: it is a public authorisation rule that
    -- the ORKs verify by VVK signature. Storing it does not let anyone decrypt anything.
    CREATE TABLE IF NOT EXISTS crypto_policy (
      id           INTEGER PRIMARY KEY CHECK (id = 1),
      contract_id  TEXT NOT NULL,
      policy_b64   TEXT NOT NULL,
      deployed_by  TEXT NOT NULL,
      deployed_at  TEXT NOT NULL
    );

    -- Append-only audit of decrypt attempts, including refusals from the ORK network.
    CREATE TABLE IF NOT EXISTS access_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      at         TEXT NOT NULL,
      username   TEXT NOT NULL,
      action     TEXT NOT NULL,
      resource   TEXT NOT NULL,
      outcome    TEXT NOT NULL,
      detail     TEXT
    );
  `);
}

/* ------------------------------------------------------------------ *
 * Types
 * ------------------------------------------------------------------ */

export interface AlertRow {
  id: string;
  created_by: string;
  created_at: string;
  tag: string;
  payload_ciphertext: string;
}

export interface ReportRow {
  id: string;
  alert_id: string | null;
  patient_id: string;
  filed_by: string;
  created_at: string;
  tag: string;
  payload_ciphertext: string;
}

export interface PatientRow {
  id: string;
  payload_ciphertext: string;
  tag: string;
  created_at: string;
}

export interface CryptoPolicyRow {
  id: number;
  contract_id: string;
  policy_b64: string;
  deployed_by: string;
  deployed_at: string;
}

/* ------------------------------------------------------------------ *
 * Queries
 * ------------------------------------------------------------------ */

export function getCryptoPolicy(): CryptoPolicyRow | null {
  return (getDb().prepare("SELECT * FROM crypto_policy WHERE id = 1").get() as CryptoPolicyRow) ?? null;
}

export function setCryptoPolicy(contractId: string, policyB64: string, deployedBy: string) {
  getDb()
    .prepare(
      `INSERT INTO crypto_policy (id, contract_id, policy_b64, deployed_by, deployed_at)
       VALUES (1, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         contract_id = excluded.contract_id,
         policy_b64  = excluded.policy_b64,
         deployed_by = excluded.deployed_by,
         deployed_at = excluded.deployed_at`
    )
    .run(contractId, policyB64, deployedBy, new Date().toISOString());
}

export function listAlertsFor(username: string, isCoordinator: boolean): AlertRow[] {
  const d = getDb();
  if (isCoordinator) {
    // A coordinator sees alerts they raised. Note "sees the row" is not "can read it" — reading
    // still requires the ORKs to decrypt, which requires the tag's role.
    return d
      .prepare("SELECT * FROM alerts WHERE created_by = ? ORDER BY created_at DESC")
      .all(username) as AlertRow[];
  }
  return d
    .prepare(
      `SELECT a.* FROM alerts a
       JOIN alert_recipients r ON r.alert_id = a.id
       WHERE r.username = ?
       ORDER BY a.created_at DESC`
    )
    .all(username) as AlertRow[];
}

export function getAlert(id: string): AlertRow | null {
  return (getDb().prepare("SELECT * FROM alerts WHERE id = ?").get(id) as AlertRow) ?? null;
}

export function isAlertRecipient(alertId: string, username: string): boolean {
  const row = getDb()
    .prepare("SELECT 1 AS x FROM alert_recipients WHERE alert_id = ? AND username = ?")
    .get(alertId, username);
  return !!row;
}

export function listAlertRecipients(alertId: string): string[] {
  return (
    getDb().prepare("SELECT username FROM alert_recipients WHERE alert_id = ?").all(alertId) as {
      username: string;
    }[]
  ).map((r) => r.username);
}

export function createAlert(
  alert: Omit<AlertRow, "created_at">,
  recipients: string[]
): AlertRow {
  const d = getDb();
  const created_at = new Date().toISOString();

  d.transaction(() => {
    d.prepare(
      `INSERT INTO alerts (id, created_by, created_at, tag, payload_ciphertext)
       VALUES (?, ?, ?, ?, ?)`
    ).run(alert.id, alert.created_by, created_at, alert.tag, alert.payload_ciphertext);

    const ins = d.prepare("INSERT OR IGNORE INTO alert_recipients (alert_id, username) VALUES (?, ?)");
    for (const u of recipients) ins.run(alert.id, u);
  })();

  return { ...alert, created_at };
}

export function isOnCareTeam(patientId: string, username: string): boolean {
  const row = getDb()
    .prepare("SELECT 1 AS x FROM care_team WHERE patient_id = ? AND username = ?")
    .get(patientId, username);
  return !!row;
}

export function listCareTeam(patientId: string): string[] {
  return (
    getDb().prepare("SELECT username FROM care_team WHERE patient_id = ? ORDER BY username").all(patientId) as {
      username: string;
    }[]
  ).map((r) => r.username);
}

export function getPatient(id: string): PatientRow | null {
  return (getDb().prepare("SELECT * FROM patients WHERE id = ?").get(id) as PatientRow) ?? null;
}

export function listPatients(): PatientRow[] {
  return getDb().prepare("SELECT * FROM patients ORDER BY created_at").all() as PatientRow[];
}

export function upsertPatient(p: Omit<PatientRow, "created_at">) {
  getDb()
    .prepare(
      `INSERT INTO patients (id, payload_ciphertext, tag, created_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET payload_ciphertext = excluded.payload_ciphertext, tag = excluded.tag`
    )
    .run(p.id, p.payload_ciphertext, p.tag, new Date().toISOString());
}

export function addCareTeamMember(patientId: string, username: string) {
  getDb()
    .prepare("INSERT OR IGNORE INTO care_team (patient_id, username, added_at) VALUES (?, ?, ?)")
    .run(patientId, username, new Date().toISOString());
}

export function createReport(r: Omit<ReportRow, "created_at">): ReportRow {
  const created_at = new Date().toISOString();
  getDb()
    .prepare(
      `INSERT INTO reports (id, alert_id, patient_id, filed_by, created_at, tag, payload_ciphertext)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(r.id, r.alert_id, r.patient_id, r.filed_by, created_at, r.tag, r.payload_ciphertext);
  return { ...r, created_at };
}

export function getReport(id: string): ReportRow | null {
  return (getDb().prepare("SELECT * FROM reports WHERE id = ?").get(id) as ReportRow) ?? null;
}

export function listReportsForPatient(patientId: string): ReportRow[] {
  return getDb()
    .prepare("SELECT * FROM reports WHERE patient_id = ? ORDER BY created_at DESC")
    .all(patientId) as ReportRow[];
}

export function listAllReports(): ReportRow[] {
  return getDb().prepare("SELECT * FROM reports ORDER BY created_at DESC").all() as ReportRow[];
}

export function logAccess(entry: {
  username: string;
  action: string;
  resource: string;
  outcome: "allowed" | "denied" | "attempted";
  detail?: string;
}) {
  getDb()
    .prepare(
      `INSERT INTO access_log (at, username, action, resource, outcome, detail)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
      new Date().toISOString(),
      entry.username,
      entry.action,
      entry.resource,
      entry.outcome,
      entry.detail ?? null
    );
}

export function recentAccessLog(limit = 50) {
  return getDb().prepare("SELECT * FROM access_log ORDER BY id DESC LIMIT ?").all(limit);
}
