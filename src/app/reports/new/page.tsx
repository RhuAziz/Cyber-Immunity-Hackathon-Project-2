"use client";

import { useEffect, useState } from "react";
import { useTideCloak } from "@tidecloak/nextjs";
import { useCrypto } from "@/lib/use-crypto";

interface PatientSummary {
  id: string;
  tag: string;
  careTeam: string[];
  requiredRole: string;
}

const DEFAULT_PATIENT_ID = "patient-1";
const DEFAULT_PATIENT_ROLE = "careteam-patient-1";

/**
 * File an incident report containing patient information.
 *
 * The report is tagged for the PATIENT'S CARE TEAM, not for the responder who wrote it and not for
 * the alert's response team. That is what makes the two access questions independent: being sent an
 * alert does not imply being allowed to read the patient notes that follow from it.
 */
export default function NewReportPage() {
  const { authenticated, isInitializing, login, hasRealmRole } = useTideCloak();
  const { api, encrypt, policyError, loading: cryptoLoading } = useCrypto();

  const [patients, setPatients] = useState<PatientSummary[]>([]);
  const [alertId, setAlertId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdId, setCreatedId] = useState<string | null>(null);

  const [patient, setPatient] = useState({
    name: "John Smith",
    dateOfBirth: "1958-04-12",
    location: "Ward 7, bed 3",
  });

  const [report, setReport] = useState({
    condition: "High fever and breathing difficulty",
    symptoms: "Temperature 39.4C, dry cough, shortness of breath on exertion",
    medication: "Medication X, 500mg twice daily",
    observations: "Patient currently being monitored. Oxygen saturation 94% on room air.",
    testResults: "Respiratory panel pending. Bloods taken at 14:20.",
    actionsTaken: "Isolated in side room. Contact precautions in place. Infection control notified.",
    incidentDetail: "Identified during routine ward round as part of the Ward 7 outbreak response.",
  });

  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    setAlertId(p.get("alertId"));
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    (async () => {
      try {
        const res = await api("/api/patients");
        if (res.ok) setPatients((await res.json()).patients);
      } catch {
        /* falls back to creating patient-1 below */
      }
    })();
  }, [authenticated, api]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const existing = patients.find((p) => p.id === DEFAULT_PATIENT_ID);
      const role = existing?.requiredRole ?? DEFAULT_PATIENT_ROLE;

      // Create the patient record on first use. Even the NAME is encrypted — for a high-profile
      // patient the identity is the secret worth stealing, so a readable name column would defeat
      // the exercise before any medical detail was involved.
      if (!existing) {
        const { ciphertext, tag } = await encrypt(patient, role);
        const pRes = await api("/api/patients", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            id: DEFAULT_PATIENT_ID,
            ciphertext,
            tag,
            // The application's care team. Note this does NOT grant the realm role above.
            careTeam: ["doctor-a", "nurse-a"],
          }),
        });
        if (!pRes.ok) throw new Error(`Could not create the patient record: ${await pRes.text()}`);
      }

      const { ciphertext, tag } = await encrypt({ ...report, patientName: patient.name }, role);

      const res = await api("/api/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ciphertext, tag, patientId: DEFAULT_PATIENT_ID, alertId }),
      });
      if (!res.ok) throw new Error(await res.text());
      setCreatedId((await res.json()).id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  if (isInitializing) return <div className="card"><h1>Starting…</h1></div>;

  if (!authenticated) {
    return (
      <div className="card">
        <h1>Sign in required</h1>
        <button className="btn" onClick={() => login()}>Sign in with Tide</button>
      </div>
    );
  }

  if (!hasRealmRole("nurse") && !hasRealmRole("doctor")) {
    return (
      <div className="card">
        <h1>Not available</h1>
        <div className="notice error">
          <h3>Clinical role required</h3>
          <p>Only a nurse or doctor may file an incident report. The API enforces this server-side.</p>
        </div>
        <a className="btn secondary" href="/dashboard">Back to dashboard</a>
      </div>
    );
  }

  if (createdId) {
    return (
      <div className="card">
        <h1>Report filed</h1>
        <div className="notice ok">
          <h3>Patient information stored as ciphertext</h3>
          <p>
            Encrypted in your browser and tagged for{" "}
            <span className="badge role">{DEFAULT_PATIENT_ROLE}</span>. Only that patient&apos;s care
            team can decrypt it — and that is enforced by the ORK network, not by our database.
          </p>
        </div>
        <dl className="kv">
          <dt>Report id</dt><dd className="mono">{createdId}</dd>
        </dl>
        <div className="btn-row">
          <a className="btn" href="/patients/patient-1">View patient record</a>
          <a className="btn secondary" href="/dashboard">Back to dashboard</a>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <h1>File an incident report</h1>
      <p className="muted">
        Everything below is encrypted before it leaves this page. The server stores an envelope and
        has no way to open it.
      </p>

      {policyError && <div className="notice warn"><h3>Encryption unavailable</h3><p>{policyError}</p></div>}

      <form onSubmit={submit}>
        <fieldset>
          <legend>Patient</legend>
          <label htmlFor="pname">Name</label>
          <input id="pname" type="text" required value={patient.name}
            onChange={(e) => setPatient({ ...patient, name: e.target.value })} />
          <label htmlFor="pdob">Date of birth</label>
          <input id="pdob" type="text" value={patient.dateOfBirth}
            onChange={(e) => setPatient({ ...patient, dateOfBirth: e.target.value })} />
          <label htmlFor="ploc">Location</label>
          <input id="ploc" type="text" value={patient.location}
            onChange={(e) => setPatient({ ...patient, location: e.target.value })} />
        </fieldset>

        <fieldset>
          <legend>Clinical detail</legend>
          <label htmlFor="cond">Condition</label>
          <input id="cond" type="text" required value={report.condition}
            onChange={(e) => setReport({ ...report, condition: e.target.value })} />
          <label htmlFor="symp">Symptoms</label>
          <textarea id="symp" value={report.symptoms}
            onChange={(e) => setReport({ ...report, symptoms: e.target.value })} />
          <label htmlFor="med">Medication</label>
          <input id="med" type="text" value={report.medication}
            onChange={(e) => setReport({ ...report, medication: e.target.value })} />
          <label htmlFor="obs">Observations</label>
          <textarea id="obs" value={report.observations}
            onChange={(e) => setReport({ ...report, observations: e.target.value })} />
          <label htmlFor="test">Test results</label>
          <textarea id="test" value={report.testResults}
            onChange={(e) => setReport({ ...report, testResults: e.target.value })} />
          <label htmlFor="act">Actions taken</label>
          <textarea id="act" value={report.actionsTaken}
            onChange={(e) => setReport({ ...report, actionsTaken: e.target.value })} />
          <label htmlFor="inc">Incident detail</label>
          <textarea id="inc" value={report.incidentDetail}
            onChange={(e) => setReport({ ...report, incidentDetail: e.target.value })} />
        </fieldset>

        {alertId && (
          <p className="muted">
            Linked to alert <span className="mono">{alertId}</span>
          </p>
        )}

        {error && <div className="notice error"><h3>Could not file the report</h3><pre>{error}</pre></div>}

        <div className="btn-row">
          <button className="btn" type="submit" disabled={submitting || cryptoLoading || !!policyError}>
            {submitting ? "Encrypting and storing…" : "Encrypt and file report"}
          </button>
          <a className="btn secondary" href="/dashboard">Cancel</a>
        </div>
      </form>
    </div>
  );
}
