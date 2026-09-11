import { NextResponse } from "next/server";
import { loadTideConfig } from "@/lib/tidecloakConfig";

/**
 * Serve the adapter config to the browser.
 *
 * Everything here is public by design: the realm, the client id, the ORK URL, and the Tide
 * **public** verification key. There is no secret in an adapter JSON — Tide clients are public
 * clients with no client secret, and `jwk` holds a public key.
 *
 * This route exists because we keep the file in `data/` rather than `public/`, so it is not served
 * as a static asset by accident.
 */
export async function GET() {
  try {
    const config = loadTideConfig();
    return NextResponse.json(config, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (err) {
    return NextResponse.json(
      {
        error: "Tide adapter config is not available",
        detail: (err as Error).message,
        hint: "Run `npm run init` to bootstrap TideCloak and export the adapter.",
      },
      { status: 503 }
    );
  }
}
