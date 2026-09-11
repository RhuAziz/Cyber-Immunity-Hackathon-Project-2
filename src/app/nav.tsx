"use client";

import { useTideCloak } from "@tidecloak/nextjs";

/**
 * Navigation and role badges.
 *
 * Every role check here is UI convenience ONLY. Hiding a link is not a security boundary — the
 * corresponding API route independently verifies the JWT and the role server-side, and would refuse
 * a hand-crafted request regardless of what this component renders.
 */
export function Nav() {
  const { authenticated, isInitializing, logout, getValueFromIdToken, hasRealmRole } =
    useTideCloak();

  const username = authenticated ? (getValueFromIdToken("preferred_username") as string) : null;

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <nav className="nav" aria-label="Main">
        <div className="nav-inner">
          <span className="brand">
            <span aria-hidden="true">🏥</span> Hospital Emergency Platform
          </span>

          {isInitializing ? (
            <span className="muted">Starting…</span>
          ) : authenticated ? (
            <>
              <a href="/dashboard">Dashboard</a>
              {hasRealmRole("coordinator") && <a href="/alerts/new">New alert</a>}
              <a href="/patients">Patients</a>
              <a href="/setup">Policy</a>
              <a href="/audit">Audit</a>
              <span className="badge role">{username}</span>
              <button className="btn secondary" onClick={() => logout()}>
                Sign out
              </button>
            </>
          ) : (
            <span className="muted">Not signed in</span>
          )}
        </div>
      </nav>
    </>
  );
}
