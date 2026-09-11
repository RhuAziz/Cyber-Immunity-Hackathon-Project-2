"use client";

import { useEffect, useState } from "react";
import { useTideCloak } from "@tidecloak/nextjs";
import { useCrypto } from "@/lib/use-crypto";
import { roleForTag } from "@/lib/crypto-client";

interface AlertSummary {
  id: string;
  createdBy: string;
  createdAt: string;
  tag: string;
  ciphertext: string;
  recipients: string[];
}

interface AlertPayload {
  title: string;
  description: string;
  emergencyType: string;
  ward: string;
  severity: string;
  occurredAt: string;
}

type Decrypted =
  | { state: "locked" }
  | { state: "open"; payload: AlertPayload }
  | { state: "denied"; requiredRole?: string; message: string };

export default function DashboardPage() {
  const { authenticated, isInitializing, login, hasRealmRole, getValueFromIdToken } = useTideCloak();
  const { api, decrypt, policyError, loading: cryptoLoading } = useCrypto();

  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [status, setStatus] = useState<Record<string, Decrypted>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const username = authenticated ? (getValueFromIdToken("preferred_username") as string) : null;

  useEffect(() => {
    if (!authenticated) return;
    (async () => {
      try {
        const res = await api("/api/alerts");
        if (!res.ok) throw new Error(await res.text());
        const j = await res.json();
        setAlerts(j.alerts);
        setStatus(Object.fromEntries(j.alerts.map((a: AlertSummary) => [a.id, { state: "locked" }])));
      } catch (err) {
        setLoadError((err as Error).message);
      }
    })();
  }, [authenticated, api]);

  const reveal = async (a: AlertSummary) => {
    setBusy(a.id);
    const result = await decrypt<AlertPayload>(a.ciphertext, a.tag, a.id, "decrypt-alert");
    setStatus((prev) => ({
      ...prev,
      [a.id]: result.ok
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

  const myRoles = [
    "coordinator", "doctor", "nurse", "hospital-admin",
    "clinical-staff", "emergency-responder",
    "response-team-infection-control", "careteam-patient-1",
  ].filter((r) => hasRealmRole(r));

  return (
    <>
      <div className="card">
        <h1>Dashboard</h1>
        <dl className="kv">
          <dt>Signed in as</dt>
          <dd>{username}</dd>
          <dt>Realm roles</dt>
          <dd>
            {myRoles.length
              ? myRoles.map((r) => <span key={r} className="badge role" style={{ marginRight: 4 }}>{r}</span>)
              : "none"}
          </dd>
        </dl>
        <p className="muted">
          The roles above are what the ORK network checks. Roles ending in a team or care-team name
          are the ones that decide what you can actually decrypt — the application cannot grant them
          to itself.
        </p>
      </div>

      {policyError && (
        <div className="card">
          <div className="notice warn">
            <h3>Encryption is unavailable</h3>
            <p>{policyError}</p>
            <a className="btn secondary" href="/setup">Go to policy setup</a>
          </div>
        </div>
      )}

      <div className="card">
        <h2>Emergency alerts</h2>
        {hasRealmRole("coordinator") && (
          <p><a className="btn" href="/alerts/new">Raise a new alert</a></p>
        )}

        {loadError && <div className="notice error"><p>{loadError}</p></div>}

        {alerts.length === 0 ? (
          <p className="muted">
            No alerts are visible to you. Either none have been raised, or you were not among the
            selected recipients.
          </p>
        ) : (
          <ul className="list">
            {alerts.map((a) => {
              const st = status[a.id] ?? { state: "locked" as const };
              return (
                <li key={a.id}>
                  <div className="btn-row" style={{ justifyContent: "space-between" }}>
                    <div>
                      <strong>
                        {st.state === "open" ? st.payload.title : "Protected alert"}
                      </strong>{" "}
                      {st.state === "locked" && <span className="badge locked">encrypted</span>}
                      {st.state === "open" && <span className="badge ok">decrypted</span>}
                      {st.state === "denied" && <span className="badge denied">access denied</span>}
                      <div className="muted">
                        raised by {a.createdBy} · {new Date(a.createdAt).toLocaleString()} ·{" "}
                        requires <span className="badge role">{roleForTag(a.tag)}</span>
                      </div>
                    </div>
                    {st.state === "locked" && (
                      <button
                        className="btn"
                        onClick={() => reveal(a)}
                        disabled={busy === a.id || cryptoLoading || !!policyError}
                      >
                        {busy === a.id ? "Asking the ORK network…" : "Decrypt"}
                      </button>
                    )}
                  </div>

                  {st.state === "open" && (
                    <>
                      <dl className="kv">
                        <dt>Emergency type</dt><dd>{st.payload.emergencyType}</dd>
                        <dt>Location</dt><dd>{st.payload.ward}</dd>
                        <dt>Severity</dt><dd>{st.payload.severity}</dd>
                        <dt>Occurred</dt><dd>{st.payload.occurredAt}</dd>
                        <dt>Detail</dt><dd>{st.payload.description}</dd>
                        <dt>Recipients</dt><dd>{a.recipients.join(", ")}</dd>
                      </dl>
                      <div className="btn-row">
                        <a className="btn secondary" href={`/reports/new?alertId=${a.id}`}>
                          File an incident report
                        </a>
                      </div>
                    </>
                  )}

                  {st.state === "denied" && (
                    <div className="notice error">
                      <h3>The ORK network refused to decrypt this</h3>
                      <p>
                        Decryption requires the realm role{" "}
                        <span className="badge role">{st.requiredRole ?? roleForTag(a.tag)}</span>,
                        which your session does not carry. This refusal came from a majority of
                        independent ORK nodes, not from this application — so it cannot be undone by
                        changing anything in our database.
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
