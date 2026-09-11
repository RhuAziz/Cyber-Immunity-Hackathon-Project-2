"use client";

import { useEffect, useState } from "react";
import { useTideCloak } from "@tidecloak/nextjs";
import { useCrypto } from "@/lib/use-crypto";

interface PatientSummary {
  id: string;
  tag: string;
  ciphertext: string;
  careTeam: string[];
  requiredRole: string;
  appAclSaysAuthorised: boolean;
}

export default function PatientsPage() {
  const { authenticated, isInitializing, login } = useTideCloak();
  const { api } = useCrypto();
  const [patients, setPatients] = useState<PatientSummary[]>([]);

  useEffect(() => {
    if (!authenticated) return;
    (async () => {
      const res = await api("/api/patients");
      if (res.ok) setPatients((await res.json()).patients);
    })();
  }, [authenticated, api]);

  if (isInitializing) return <div className="card"><h1>Starting…</h1></div>;
  if (!authenticated) {
    return (
      <div className="card">
        <h1>Sign in required</h1>
        <button className="btn" onClick={() => login()}>Sign in with Tide</button>
      </div>
    );
  }

  return (
    <div className="card">
      <h1>Patients</h1>
      {patients.length === 0 ? (
        <p className="muted">
          No patient records yet. One is created when the first incident report is filed.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Record</th>
              <th>Decrypt requires</th>
              <th>App care team</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {patients.map((p) => (
              <tr key={p.id}>
                <td className="mono">{p.id}</td>
                <td><span className="badge role">{p.requiredRole}</span></td>
                <td className="muted">{p.careTeam.join(", ") || "none"}</td>
                <td><a className="btn secondary" href={`/patients/${p.id}`}>Open</a></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted">
        The two middle columns are the point of this project. The left one is enforced by the ORK
        network and cannot be changed from here. The right one is a table in our SQLite file, and an
        administrator can rewrite it at will — which is exactly what{" "}
        <span className="mono">npm run attack:admin-escalate</span> does.
      </p>
    </div>
  );
}
