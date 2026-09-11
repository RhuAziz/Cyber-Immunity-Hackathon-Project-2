"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { useTideCloak } from "@tidecloak/nextjs";
import { useCrypto } from "@/lib/use-crypto";
import { roleForTag } from "@/lib/crypto-client";

interface ReportSummary {
  id: string;
  patientId: string;
  filedBy: string;
  createdAt: string;
  tag: string;
  ciphertext: string;
  requiredRole: string;
  appAclSaysAuthorised: boolean;
}

interface ReportPayload {
  patientName?: string;
  condition: string;
  symptoms: string;
  medication: string;
  observations: string;
  testResults: string;
  actionsTaken: string;
  incidentDetail: string;
}

type State =
  | { state: "locked" }
  | { state: "open"; payload: ReportPayload }
  | { state: "denied"; requiredRole?: string; message: string };

/**
 * The patient record page. This is where the headline demonstration lands.
 *
 * We deliberately show the application ACL's verdict NEXT TO the ORK network's verdict. When an
 * administrator rewrites the care_team table, the left column flips to "authorised" and the right
 * column still refuses — which is the entire claim of the project, made visible on one screen.
 */
export default function PatientPage() {
  const params = useParams<{ id: string }>();
  const patientId = params.id;

  const { authenticated, isInitializing, login, getValueFromIdToken } = useTideCloak();
  const { api, decrypt, policyError, loading: cryptoLoading } = useCrypto();

  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [status, setStatus] = useState<Record<string, State>>({});
  const [careTeam, setCareTeam] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  const username = authenticated ? (getValueFromIdToken("preferred_username") as string) : null;

  useEffect(() => {
    if (!authenticated) return;
    (async () => {
      const [rRes, pRes] = await Promise.all([
        api(`/api/reports?patientId=${encodeURIComponent(patientId)}`),
        api("/api/patients"),
      ]);
      if (rRes.ok) {
        const j = await rRes.json();
        setReports(j.reports);
        setStatus(Object.fromEntries(j.reports.map((r: ReportSummary) => [r.id, { state: "locked" }])));
      }
      if (pRes.ok) {
        const j = await pRes.json();
        setCareTeam(j.patients.find((p: { id: string }) => p.id === patientId)?.careTeam ?? []);
      }
    })();
  }, [authenticated, api, patientId]);

  const reveal = async (r: ReportSummary) => {
    setBusy(r.id);
    const result = await decrypt<ReportPayload>(r.ciphertext, r.tag, r.id, "decrypt-report");
    setStatus((prev) => ({
      ...prev,
      [r.id]: result.ok
        ? { state: "open", payload: result.data }
        : { state: "denied", requiredRole: result.deniedRole, message: result.message },
    }));
    setBusy(null);
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

  const appSaysYes = careTeam.includes(username ?? "");

  return (
    <>
      <div className="card">
        <h1>Patient record <span className="mono">{patientId}</span></h1>

        <h2>Who does each layer think you are?</h2>
        <table>
          <thead>
            <tr><th>Layer</th><th>Verdict</th><th>Stored where</th></tr>
          </thead>
          <tbody>
            <tr>
              <td>Application care team</td>
              <td>
                {appSaysYes
                  ? <span className="badge ok">authorised</span>
                  : <span className="badge denied">not authorised</span>}
              </td>
              <td className="muted">
                <span className="mono">care_team</span> table in <span className="mono">data/hospital.db</span> — writable by any administrator
              </td>
            </tr>
            <tr>
              <td>ORK network (Forseti contract)</td>
              <td><span className="muted">decided per decrypt attempt, below</span></td>
              <td className="muted">
                realm roles in TideCloak, IGA-governed — cannot be self-granted
              </td>
            </tr>
          </tbody>
        </table>
        <p className="muted">Application care team: {careTeam.join(", ") || "empty"}</p>
      </div>

      {policyError && (
        <div className="card"><div className="notice warn"><h3>Encryption unavailable</h3><p>{policyError}</p></div></div>
      )}

      <div className="card">
        <h2>Incident reports</h2>
        {reports.length === 0 ? (
          <p className="muted">No reports for this patient yet.</p>
        ) : (
          <ul className="list">
            {reports.map((r) => {
              const st = status[r.id] ?? { state: "locked" as const };
              return (
                <li key={r.id}>
                  <div className="btn-row" style={{ justifyContent: "space-between" }}>
                    <div>
                      <strong>Report</strong>{" "}
                      {st.state === "locked" && <span className="badge locked">encrypted</span>}
                      {st.state === "open" && <span className="badge ok">decrypted</span>}
                      {st.state === "denied" && <span className="badge denied">access denied</span>}
                      <div className="muted">
                        filed by {r.filedBy} · {new Date(r.createdAt).toLocaleString()} · requires{" "}
                        <span className="badge role">{roleForTag(r.tag)}</span>
                      </div>
                    </div>
                    {st.state === "locked" && (
                      <button className="btn" onClick={() => reveal(r)}
                        disabled={busy === r.id || cryptoLoading || !!policyError}>
                        {busy === r.id ? "Asking the ORK network…" : "Decrypt"}
                      </button>
                    )}
                  </div>

                  {st.state === "open" && (
                    <dl className="kv">
                      {st.payload.patientName && (<><dt>Patient</dt><dd>{st.payload.patientName}</dd></>)}
                      <dt>Condition</dt><dd>{st.payload.condition}</dd>
                      <dt>Symptoms</dt><dd>{st.payload.symptoms}</dd>
                      <dt>Medication</dt><dd>{st.payload.medication}</dd>
                      <dt>Observations</dt><dd>{st.payload.observations}</dd>
                      <dt>Test results</dt><dd>{st.payload.testResults}</dd>
                      <dt>Actions taken</dt><dd>{st.payload.actionsTaken}</dd>
                      <dt>Incident</dt><dd>{st.payload.incidentDetail}</dd>
                    </dl>
                  )}

                  {st.state === "denied" && (
                    <div className="notice error">
                      <h3>The ORK network refused to decrypt this</h3>
                      <p>
                        Reading this report requires the realm role{" "}
                        <span className="badge role">{st.requiredRole ?? roleForTag(r.tag)}</span>.
                        {appSaysYes && (
                          <>
                            {" "}
                            <strong>
                              Note that the application&apos;s care-team table says you ARE
                              authorised, and it made no difference.
                            </strong>{" "}
                            The refusal came from a majority of independent ORK nodes checking the
                            roles in your session token, so rewriting our database achieves nothing.
                          </>
                        )}
                      </p>
                      <details>
                        <summary>Network response</summary>
                        <pre>{st.message}</pre>
                      </details>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </>
  );
}
