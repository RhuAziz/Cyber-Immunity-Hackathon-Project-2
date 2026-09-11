"use client";

import { useEffect } from "react";
import { useTideCloak } from "@tidecloak/nextjs";

export default function LoginPage() {
  const { authenticated, isInitializing, login } = useTideCloak();

  useEffect(() => {
    if (authenticated) window.location.assign("/dashboard");
  }, [authenticated]);

  const authError =
    typeof window !== "undefined" && new URLSearchParams(window.location.search).has("authError");

  return (
    <>
      <div className="card">
        <h1>Hospital Emergency Platform</h1>
        <p className="muted">
          Emergency alerting and incident reporting where sensitive content stays unreadable to
          anyone the Tide network has not authorised — including whoever controls this application
          and its database.
        </p>

        {authError && (
          <div className="notice error">
            <h3>Sign-in did not complete</h3>
            <p>The authorisation code could not be exchanged. Please try again.</p>
          </div>
        )}

        {isInitializing ? (
          <p className="muted">Starting TideCloak…</p>
        ) : (
          <button className="btn" onClick={() => login()}>
            Sign in with Tide
          </button>
        )}

        <div className="notice info">
          <h3>There is no password stored anywhere</h3>
          <p>
            Tide authenticates through a threshold protocol across a network of independent nodes.
            No node, and not this application, ever learns your passphrase, and no password hash
            exists to steal. Each account is enrolled from its own invitation link, which is why
            there are no seeded credentials to hand out.
          </p>
        </div>
      </div>

      <div className="card">
        <h2>What this proof of concept demonstrates</h2>
        <table>
          <thead>
            <tr>
              <th>Scenario</th>
              <th>Expected result</th>
              <th>Enforced by</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>An authorised responder opens an alert</td>
              <td>Readable</td>
              <td>ORK network + app ACL</td>
            </tr>
            <tr>
              <td>A doctor outside the response team opens the same alert</td>
              <td>Denied</td>
              <td>ORK network (missing tag role)</td>
            </tr>
            <tr>
              <td>A care-team doctor opens a patient report</td>
              <td>Readable</td>
              <td>ORK network</td>
            </tr>
            <tr>
              <td>A doctor from another ward opens that report</td>
              <td>Denied</td>
              <td>ORK network (missing tag role)</td>
            </tr>
            <tr>
              <td>The database is stolen and inspected</td>
              <td>Ciphertext only</td>
              <td>Encryption before storage</td>
            </tr>
            <tr>
              <td>An administrator adds themselves to the care team in SQL</td>
              <td>Still denied</td>
              <td>ORK network — the app ACL is not the authority</td>
            </tr>
          </tbody>
        </table>
        <p className="muted">
          The last two are the ones worth watching. Run them yourself with{" "}
          <span className="mono">npm run attack:steal-db</span> and{" "}
          <span className="mono">npm run attack:admin-escalate</span>.
        </p>
      </div>
    </>
  );
}
