import { NextResponse } from "next/server";
import { verifyTideJWT, extractBearer, AuthError, type TideJWT } from "./tideJWT";
import { logAccess } from "./db";

/**
 * Server-side authorization wrapper for API routes.
 *
 * This is where authorization actually happens. `proxy.ts` redirects and hidden buttons are UI
 * gating; an attacker just calls the route directly. So every protected route goes through here.
 */

export interface AuthedRequest {
  jwt: TideJWT;
  username: string;
  roles: string[];
  /** Tide's per-vendor user id. This, not `sub`, is the identity the ORK network works with. */
  vuid: string | undefined;
}

type Handler = (req: Request, ctx: AuthedRequest, params: Record<string, string>) => Promise<Response>;

export function withAuth(handler: Handler, opts: { requireAnyRole?: string[] } = {}) {
  // The second parameter must NOT be optional. Next.js 16 generates a ParamCheck against its own
  // RouteContext, and an optional param widens the type to `... | undefined`, which fails the check
  // for every route with "Type 'undefined' is not assignable to type 'RouteContext'".
  // Next.js 16 requires the second parameter to be present and to carry `params` as a PROMISE.
  // Making it optional, or allowing a plain object, fails the generated ParamCheck for every route
  // with "Type 'undefined' is not assignable to type 'Promise<any>'".
  return async (
    req: Request,
    routeCtx: { params: Promise<Record<string, string>> }
  ): Promise<Response> => {
    let jwt: TideJWT;

    try {
      jwt = await verifyTideJWT(extractBearer(req));
    } catch (err) {
      const status = err instanceof AuthError ? err.status : 401;
      return NextResponse.json(
        { error: "Unauthorized", detail: (err as Error).message },
        { status }
      );
    }

    const username = (jwt.preferred_username as string) ?? "unknown";
    const roles = jwt.realm_access?.roles ?? [];

    if (opts.requireAnyRole?.length) {
      const permitted = opts.requireAnyRole.some((r) => roles.includes(r));
      if (!permitted) {
        // Log refusals: an audit trail of denied attempts is part of what makes the demo legible.
        logAccess({
          username,
          action: "api",
          resource: new URL(req.url).pathname,
          outcome: "denied",
          detail: `requires one of: ${opts.requireAnyRole.join(", ")}`,
        });
        return NextResponse.json(
          {
            error: "Forbidden",
            detail: `This action requires one of: ${opts.requireAnyRole.join(", ")}`,
            yourRoles: roles,
          },
          { status: 403 }
        );
      }
    }

    // Static routes get no params; dynamic ones get a promise. Tolerate both.
    const params = (await routeCtx?.params) ?? {};

    try {
      return await handler(
        req,
        { jwt, username, roles, vuid: jwt.vuid as string | undefined },
        params as Record<string, string>
      );
    } catch (err) {
      console.error(`[api] ${new URL(req.url).pathname} failed:`, err);
      return NextResponse.json(
        { error: "Internal error", detail: (err as Error).message },
        { status: 500 }
      );
    }
  };
}
