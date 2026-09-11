import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/**
 * The adapter JSON exported from TideCloak. This is NOT a standard Keycloak adapter — the three
 * Tide extension fields at the bottom are what make local JWT verification and Fabric access
 * possible, and a generic Keycloak export does not contain them.
 */
export interface TideConfig {
  realm: string;
  "auth-server-url": string;
  resource: string;
  "ssl-required": string;
  "public-client": boolean;
  "confidential-port": number;

  /** Embedded JWKS. Present because Tide uses a non-rotating vendor-verifiable key. */
  jwk: { keys: unknown[] };
  vendorId: string;
  homeOrkUrl: string;

  /** One `client-origin-auth-<origin>` per allowed web origin, signed by the ORK network. */
  [key: string]: unknown;
}

let cached: TideConfig | null = null;

/**
 * Load the adapter config server-side.
 *
 * Priority is env var then file, so a container deployment can inject the config without a
 * bind mount.
 */
export function loadTideConfig(): TideConfig {
  if (cached) return cached;

  let parsed: TideConfig;

  if (process.env.CLIENT_ADAPTER) {
    parsed = JSON.parse(process.env.CLIENT_ADAPTER);
  } else if (process.env.TIDECLOAK_CONFIG_B64) {
    parsed = JSON.parse(Buffer.from(process.env.TIDECLOAK_CONFIG_B64, "base64").toString("utf8"));
  } else {
    const path = resolve(process.cwd(), "data", "tidecloak.json");
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new Error(
        `Could not read the Tide adapter config at ${path}.\n` +
          "Run `npm run init` to bootstrap TideCloak and export it."
      );
    }
  }

  // Validate the Tide extensions at load time rather than discovering the gap during a request.
  //
  // A missing `jwk` is a SETUP failure, not a code path to work around. The temptation is to fall
  // back to fetching keys from the realm's certs endpoint with `createRemoteJWKSet` — the shipped
  // @tidecloak/verify will even do that for you. We deliberately do not: that reintroduces a
  // network dependency in the verification path and an interception point, and it masks the real
  // problem (licensing or IGA did not complete) instead of surfacing it.
  const missing: string[] = [];
  if (!parsed.jwk) missing.push("jwk");
  if (!parsed.vendorId) missing.push("vendorId");
  if (!parsed.homeOrkUrl) missing.push("homeOrkUrl");

  if (missing.length) {
    throw new Error(
      `Tide adapter config is missing: ${missing.join(", ")}.\n` +
        "Re-export the adapter from TideCloak with licensing and IGA complete.\n" +
        "Do not hand-build this file and do not switch to remote JWKS fetching."
    );
  }

  cached = parsed;
  return parsed;
}

/** The issuer string TideCloak puts in the `iss` claim. */
export function expectedIssuer(config: TideConfig = loadTideConfig()): string {
  return `${config["auth-server-url"].replace(/\/+$/, "")}/realms/${config.realm}`;
}
