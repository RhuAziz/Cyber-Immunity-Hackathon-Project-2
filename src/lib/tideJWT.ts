import { createLocalJWKSet, jwtVerify, type JWTPayload } from "jose";
import { loadTideConfig, expectedIssuer } from "./tidecloakConfig";

/**
 * Server-side JWT verification. This is the ONLY authorization boundary in the app.
 *
 * Anything the browser decides — `hasRealmRole()`, a hidden button, a redirect in `proxy.ts` — is
 * UI convenience. It is trivially bypassed by calling the API directly, so none of it is relied on
 * here.
 *
 * Note what makes these tokens unusual: they are not signed by the TideCloak server. Signing is a
 * threshold operation across the ORK network, where each ORK independently verifies the claims
 * before contributing a partial signature. So a fully compromised TideCloak server still cannot
 * mint a token that passes this check.
 */

export interface TideJWT extends JWTPayload {
  azp?: string;
  preferred_username?: string;
  vuid?: string;
  tideuserkey?: string;
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
  /** DPoP confirmation claim. Its presence proves TideCloak bound this token at issuance. */
  cnf?: { jkt?: string };
}

export class AuthError extends Error {
  status: number;
  constructor(message: string, status = 401) {
    super(message);
    this.status = status;
  }
}

// Build the key set ONCE from the embedded JWKS. createLocalJWKSet, never createRemoteJWKSet:
// verification must not depend on a network call to the very server whose tokens it is checking.
const config = loadTideConfig();
const JWKS = createLocalJWKSet(config.jwk as Parameters<typeof createLocalJWKSet>[0]);
const ISSUER = expectedIssuer(config);

/**
 * Whether DPoP token binding is in force. Must agree with the client's provider config and with
 * the `dpop.bound.access.tokens` attribute on the TideCloak client — `scripts/set-dpop.mjs`
 * changes all three together, because changing one alone breaks login rather than degrading it.
 *
 * Currently OFF, and that is a known HIGH-severity gap, not a preference. See docs/SECURITY-GAPS.md.
 */
export const DPOP_ENABLED = process.env.NEXT_PUBLIC_TIDE_DPOP === "on";

if (!DPOP_ENABLED) {
  console.warn(
    "[tideJWT] DPoP is DISABLED. Access tokens are plain bearer tokens and a stolen token " +
      "can be replayed from another device. See docs/SECURITY-GAPS.md (SG-03)."
  );
}

export async function verifyTideJWT(token: string): Promise<TideJWT> {
  let payload: TideJWT;

  try {
    const result = await jwtVerify(token, JWKS, { issuer: ISSUER });
    payload = result.payload as TideJWT;
  } catch (err) {
    // ERR_JWKS_NO_MATCHING_KEY here means the adapter JSON is stale relative to the realm.
    // The fix is re-exporting the adapter, not loosening verification.
    throw new AuthError(`Token verification failed: ${(err as Error).message}`, 401);
  }

  // TideCloak access tokens carry the client id in `azp`. The `aud` claim is "account", so
  // checking `aud` against the client id looks correct and always fails.
  if (payload.azp !== config.resource) {
    throw new AuthError("Token azp does not match this client", 401);
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp < now) {
    throw new AuthError("Token expired", 401);
  }
  if (typeof payload.iat === "number" && payload.iat > now + 60) {
    throw new AuthError("Token issued in the future", 401);
  }

  // DPoP binding check. When DPoP is on this FAILS CLOSED.
  //
  // `cnf.jkt` is present only when TideCloak bound the token to a client key pair at issuance, so
  // asserting it is what proves the binding actually happened. Omitting this assertion is the
  // silent failure mode: the app enables DPoP client-side, believes it is protected, and still
  // accepts an unbound bearer token lifted from a log or a proxy.
  //
  // We assert `cnf.jkt` rather than re-verifying the proof itself deliberately. With `secureFetch`
  // the proofs are Tide-specific and NOT RFC 9449 compact JWS, so calling jwtVerify() on the DPoP
  // header throws "Invalid Compact JWS". `cnf.jkt` is the meaningful signal available here.
  if (DPOP_ENABLED) {
    if (!payload.cnf?.jkt) {
      throw new AuthError("Access token is not DPoP-bound", 401);
    }
  } else if (payload.cnf?.jkt) {
    // DPoP is off by configuration but the token is bound anyway, so the two halves have drifted
    // apart. Accept the token (it is strictly stronger) but say so, because a half-configured
    // DPoP setup is exactly what produces confusing login failures.
    console.warn(
      "[tideJWT] Token carries cnf.jkt but NEXT_PUBLIC_TIDE_DPOP is off. " +
        "Server and client DPoP settings have drifted; run `node scripts/set-dpop.mjs on`."
    );
  }

  return payload;
}

export function realmRoles(jwt: TideJWT): string[] {
  return jwt.realm_access?.roles ?? [];
}

export function hasRealmRole(jwt: TideJWT, role: string): boolean {
  return realmRoles(jwt).includes(role);
}

export function extractBearer(req: Request): string {
  const header = req.headers.get("authorization");
  if (!header) throw new AuthError("Missing Authorization header", 401);

  // secureFetch sends `Bearer <token>` with a separate DPoP header. Accept the DPoP scheme too,
  // since hand-rolled RFC 9449 clients use `Authorization: DPoP <token>`.
  const match = /^(Bearer|DPoP)\s+(.+)$/i.exec(header.trim());
  if (!match) throw new AuthError("Malformed Authorization header", 401);
  return match[2];
}
