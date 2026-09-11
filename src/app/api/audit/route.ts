import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import { recentAccessLog, logAccess } from "@/lib/db";

/** Recent access attempts, including refusals. */
export const GET = withAuth(async () => {
  return NextResponse.json({ entries: recentAccessLog(100) });
});

/**
 * Record a decrypt outcome reported by the browser.
 *
 * Decryption happens client-side by necessity, so the server cannot observe it directly. This lets
 * the client tell us what the ORK network decided, which is what makes the refusals visible in the
 * audit trail.
 *
 * Note honestly what this log is and is not: it is a convenience record, reported by the client and
 * therefore not trustworthy evidence. It is useful for demonstrating and debugging, and it is not a
 * security control. The actual enforcement happened at the ORKs before this call was made.
 */
export const POST = withAuth(async (req, ctx) => {
  const body = (await req.json()) as {
    action?: string;
    resource?: string;
    outcome?: "allowed" | "denied" | "attempted";
    detail?: string;
  };

  if (!body.action || !body.resource || !body.outcome) {
    return NextResponse.json({ error: "action, resource and outcome are required" }, { status: 400 });
  }

  logAccess({
    username: ctx.username,
    action: body.action,
    resource: body.resource,
    outcome: body.outcome,
    detail: body.detail?.slice(0, 500),
  });

  return NextResponse.json({ ok: true });
});
