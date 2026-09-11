"use client";

import { useEffect, useState } from "react";
import { useTideCloak } from "@tidecloak/nextjs";
import { useCrypto } from "@/lib/use-crypto";

interface Entry {
  id: number;
  at: string;
  username: string;
  action: string;
  resource: string;
  outcome: string;
  detail: string | null;
}

export default function AuditPage() {
  const { authenticated, isInitializing, login } = useTideCloak();
  const { api } = useCrypto();
  const [entries, setEntries] = useState<Entry[]>([]);

  useEffect(() => {
    if (!authenticated) return;
    (async () => {
      const res = await api("/api/audit");
      if (res.ok) setEntries((await res.json()).entries);
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
      <h1>Access log</h1>
      <div className="notice info">
        <h3>What this log is, and what it is not</h3>
        <p>
          Decryption happens in the browser, so the server cannot observe it directly — the client
          reports the outcome here. That makes this a useful record for demonstration and debugging,
          and <strong>not</strong> trustworthy evidence: a hostile client could lie to it. The actual
          enforcement already happened at the ORK network before any of these rows were written.
        </p>
      </div>

      {entries.length === 0 ? (
        <p className="muted">Nothing logged yet.</p>
      ) : (
        <table>
          <thead>
            <tr><th>When</th><th>Who</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Detail</th></tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="muted">{new Date(e.at).toLocaleTimeString()}</td>
                <td>{e.username}</td>
                <td className="mono">{e.action}</td>
                <td className="mono">{e.resource.slice(0, 14)}…</td>
                <td>
                  <span className={`badge ${e.outcome === "allowed" ? "ok" : "denied"}`}>
                    {e.outcome}
                  </span>
                </td>
                <td className="muted" style={{ maxWidth: "22rem" }}>{e.detail ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
