"use client";

import { useAuthCallback } from "@tidecloak/nextjs";
import { useEffect, useState } from "react";

/**
 * Post-auth redirect handler (I-16).
 *
 * The path is `/auth/redirect`, NOT `/auth/callback`. Almost every other OIDC integration uses
 * `callback`, so it is the name you reach for by reflex, and getting it wrong fails in the worst
 * possible way: TideCloak authenticates the user, redirects back with `?code=...`, the app 404s,
 * the SDK never runs, and NO error appears anywhere. Login just silently does nothing.
 *
 * The page must also actively PROCESS the callback. A placeholder that only renders text leaves
 * the auth code unexchanged.
 */

function RedirectHandler() {
  const { isProcessing, isSuccess, error } = useAuthCallback({
    onSuccess: (returnUrl) => window.location.assign(returnUrl || "/dashboard"),
    onError: () => window.location.assign("/?authError=1"),
    onMissingVerifierRedirectTo: "/",
  });

  useEffect(() => {
    // Landing here without a code or error means someone navigated directly. Bounce home rather
    // than sitting on a spinner forever.
    const params = new URLSearchParams(window.location.search);
    if (!params.has("code") && !params.has("error")) {
      window.location.assign("/");
    }
  }, []);

  if (error) {
    return (
      <div className="card">
        <h1>Sign-in failed</h1>
        <p className="muted">{error.message}</p>
        <a className="btn" href="/">
          Back to sign in
        </a>
      </div>
    );
  }

  if (isProcessing || !isSuccess) {
    return (
      <div className="card">
        <h1>Completing sign-in…</h1>
        <p className="muted">Exchanging the authorisation code with TideCloak.</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h1>Signed in</h1>
      <p className="muted">Redirecting…</p>
    </div>
  );
}

export default function AuthRedirectPage() {
  // useAuthCallback touches `window`, so it must not run during SSR. Gate on mount.
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!mounted) {
    return (
      <div className="card">
        <h1>Loading…</h1>
      </div>
    );
  }
  return <RedirectHandler />;
}
