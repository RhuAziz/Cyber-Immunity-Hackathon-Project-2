"use client";

import { useEffect, useState } from "react";
import { useTideCloak } from "@tidecloak/nextjs";
import { useCrypto } from "@/lib/use-crypto";

interface StaffMember {
  username: string;
  name: string;
  roles: string[];
  enrolled: boolean;
}

/**
 * Raise an emergency alert.
 *
 * The response team choice is the important control on this page. It sets the ciphertext tag, and
 * the tag is what the ORK network turns into a role requirement — so choosing
 * "infection control" genuinely restricts who can decrypt the alert, rather than only filtering a
 * list. The recipient checkboxes are the application's own ACL on top of that.
 */
export default function NewAlertPage() {
  const { authenticated, isInitializing, login, hasRealmRole } = useTideCloak();
  const { api, encrypt, policyError, loading: cryptoLoading } = useCrypto();

  const [staff, setStaff] = useState<StaffMember[]>([]);
  const [recipients, setRecipients] = useState<string[]>([]);
  const [team, setTeam] = useState("response-team-infection-control");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdId, setCreatedId] = useState<string | null>(null);

  const [form, setForm] = useState({
    title: "Possible infectious outbreak detected in Ward 7",
    description:
      "Suspected infectious outbreak identified during routine observation. Investigation required. Restrict non-essential movement in and out of the ward until infection control has assessed.",
    emergencyType: "Infectious disease outbreak",
    ward: "Ward 7",
    severity: "High",
    occurredAt: new Date().toISOString().slice(0, 16),
  });

  useEffect(() => {
    if (!authenticated) return;
    (async () => {
      try {
        const res = await api("/api/users");
        if (res.ok) {
          const j = await res.json();
          setStaff(j.staff);
          // Pre-select the members of the chosen team who can actually decrypt, which makes the
          // demo's intent obvious without hiding the choice.
          setRecipients(
            j.staff
              .filter((s: StaffMember) => s.roles.includes(team) && s.roles.includes("clinical-staff"))
              .map((s: StaffMember) => s.username)
          );
        }
      } catch {
        /* the list is a convenience; the form still works */
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated, api]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      // Encrypt EVERYTHING sensitive in the browser before it goes anywhere. The ward and severity
      // are included deliberately: knowing that Ward 7 is at high severity before any public
      // announcement is itself valuable to an attacker.
      const { ciphertext, tag } = await encrypt(form, team);

      const res = await api("/api/alerts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ciphertext, tag, recipients }),
      });

      if (!res.ok) throw new Error(await res.text());
      const j = await res.json();
      setCreatedId(j.id);
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

  // UI gating only. POST /api/alerts independently requires the coordinator role server-side.
  if (!hasRealmRole("coordinator")) {
    return (
      <div className="card">
        <h1>Not available</h1>
        <div className="notice error">
          <h3>Coordinator role required</h3>
          <p>
            Only a coordinator can raise alerts. Hiding this form is cosmetic — the API refuses the
            request server-side after verifying your token, so calling it directly fails too.
          </p>
        </div>
        <a className="btn secondary" href="/dashboard">Back to dashboard</a>
      </div>
    );
  }

  if (createdId) {
    return (
      <div className="card">
        <h1>Alert raised</h1>
        <div className="notice ok">
          <h3>Stored as ciphertext</h3>
          <p>
            The alert body was encrypted in your browser and the server received only the envelope.
            Only holders of <span className="badge role">{team}</span> can decrypt it.
          </p>
        </div>
        <dl className="kv">
          <dt>Alert id</dt><dd className="mono">{createdId}</dd>
          <dt>Recipients</dt><dd>{recipients.join(", ") || "none"}</dd>
        </dl>
        <div className="btn-row">
          <a className="btn" href="/dashboard">Back to dashboard</a>
          <a className="btn secondary" href={`/reports/new?alertId=${createdId}`}>File a report</a>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <h1>Raise an emergency alert</h1>

      {policyError && (
        <div className="notice warn">
          <h3>Encryption unavailable</h3>
          <p>{policyError}</p>
        </div>
      )}

      <form onSubmit={submit}>
        <label htmlFor="title">Title</label>
        <input id="title" type="text" required value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })} />

        <label htmlFor="desc">Description</label>
        <textarea id="desc" required value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })} />

        <label htmlFor="etype">Emergency type</label>
        <input id="etype" type="text" required value={form.emergencyType}
          onChange={(e) => setForm({ ...form, emergencyType: e.target.value })} />

        <label htmlFor="ward">Ward / location</label>
        <input id="ward" type="text" required value={form.ward}
          onChange={(e) => setForm({ ...form, ward: e.target.value })} />

        <label htmlFor="sev">Severity</label>
        <select id="sev" value={form.severity}
          onChange={(e) => setForm({ ...form, severity: e.target.value })}>
          <option>Low</option><option>Moderate</option><option>High</option><option>Critical</option>
        </select>

        <label htmlFor="when">Date and time</label>
        <input id="when" type="datetime-local" value={form.occurredAt}
          onChange={(e) => setForm({ ...form, occurredAt: e.target.value })} />

        <label htmlFor="team">Response team (this sets the cryptographic restriction)</label>
        <select id="team" value={team} onChange={(e) => setTeam(e.target.value)}>
          <option value="response-team-infection-control">Infection control response team</option>
          <option value="emergency-responder">All emergency responders (wider)</option>
        </select>
        <p className="muted">
          The alert is tagged <span className="mono">hosp:{team}</span>. The ORK network will demand
          the realm role <span className="badge role">{team}</span> from anyone attempting to
          decrypt it, regardless of the recipient list below.
        </p>

        <fieldset>
          <legend>Recipients (application access control)</legend>
          <p className="muted">
            Who sees the alert listed in their dashboard. This is enforced by our API, and it is
            stored in our database — so unlike the role requirement above, it is not protected
            against someone who can write to that database.
          </p>
          {staff.length === 0 ? (
            <p className="muted">Loading staff directory…</p>
          ) : (
            staff.map((s) => {
              const canDecrypt = s.roles.includes(team);
              return (
                <label key={s.username} className="check">
                  <input
                    type="checkbox"
                    checked={recipients.includes(s.username)}
                    onChange={(e) =>
                      setRecipients((prev) =>
                        e.target.checked
                          ? [...prev, s.username]
                          : prev.filter((u) => u !== s.username)
                      )
                    }
                  />
                  <span>
                    {s.name} <span className="mono muted">({s.username})</span>{" "}
                    {canDecrypt ? (
                      <span className="badge ok">can decrypt</span>
                    ) : (
                      <span className="badge denied">cannot decrypt</span>
                    )}
                    {!s.enrolled && <span className="badge locked"> not enrolled</span>}
                    <br />
                    <span className="muted mono">{s.roles.join(", ")}</span>
                  </span>
                </label>
              );
            })
          )}
        </fieldset>

        {error && <div className="notice error"><h3>Could not raise the alert</h3><pre>{error}</pre></div>}

        <div className="btn-row">
          <button className="btn" type="submit"
            disabled={submitting || cryptoLoading || !!policyError || recipients.length === 0}>
            {submitting ? "Encrypting and storing…" : "Encrypt and raise alert"}
          </button>
          <a className="btn secondary" href="/dashboard">Cancel</a>
        </div>
      </form>
    </div>
  );
}
