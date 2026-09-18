"use client";

/**
 * Attach the current Tide access token before calling the SDK request helper.
 *
 * @tidecloak/js 0.14.20's secureFetch adds the Authorization header in its DPoP path,
 * but its DPoP-off path delegates directly to fetch(url, init). Supplying the token here
 * makes bearer mode work and remains compatible with DPoP: secureFetch recognises its own
 * current bearer token and replaces it with the DPoP scheme when DPoP is enabled.
 */
export async function authenticatedFetch(
  secureFetch: (url: string | URL, init?: RequestInit) => Promise<Response>,
  getToken: () => Promise<string | null>,
  url: string | URL,
  init: RequestInit = {}
): Promise<Response> {
  const token = await getToken();
  if (!token) {
    throw new Error("No Tide access token is available; sign in again.");
  }

  const headers = new Headers(init.headers);
  if (!headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return secureFetch(url, { ...init, headers });
}
