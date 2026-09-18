import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import {
  deleteAlertAndAudit,
  getAlert,
  isAlertRecipient,
  listAlertRecipients,
  logAccess,
} from "@/lib/db";

/**
 * A single alert's ciphertext.
 *
 * TWO INDEPENDENT LAYERS GUARD THIS, and it is worth being precise about which does what:
 *
 *   Layer 2 (here, application ACL)  Were you on the recipient list? Enforced by this route after
 *                                    server-side JWT verification. It protects against an ordinary
 *                                    user poking at URLs — but it lives in SQLite, so it does NOT
 *                                    protect against an attacker who can write to the database.
 *
 *   Layer 1 (the ORK network)        Even holding the ciphertext, decryption requires a doken
 *                                    carrying the realm role the tag names. That is enforced by a
 *                                    majority of independent ORKs running our Forseti contract, and
 *                                    editing this database cannot affect it.
 *
 * So this route being bypassed leaks envelopes, not content. That distinction is the whole point of
 * the project, and it is why we return the ciphertext with the required role named: the client can
 * explain a refusal honestly instead of pretending the app decided it.
 */

export const GET = withAuth(async (req, ctx, params) => {
  const alert = getAlert(params.id);

  if (!alert) {
    return NextResponse.json({ error: "Alert not found" }, { status: 404 });
  }

  const isRecipient = isAlertRecipient(alert.id, ctx.username);
  const isAuthor = alert.created_by === ctx.username;

  if (!isRecipient && !isAuthor) {
    logAccess({
      username: ctx.username,
      action: "view-alert",
      resource: alert.id,
      outcome: "denied",
      detail: "not on the recipient list (application ACL)",
    });

    return NextResponse.json(
      {
        error: "Access denied",
        layer: "application-acl",
        detail:
          "You are not a recipient of this alert. Note this is the application's own access " +
          "control. Independently, the ORK network would refuse to decrypt without the role " +
          `"${alert.tag.replace(/^hosp:/, "")}".`,
      },
      { status: 403 }
    );
  }

  logAccess({
    username: ctx.username,
    action: "view-alert",
    resource: alert.id,
    outcome: "allowed",
    detail: isAuthor ? "author" : "recipient",
  });

  return NextResponse.json({
    id: alert.id,
    createdBy: alert.created_by,
    createdAt: alert.created_at,
    tag: alert.tag,
    ciphertext: alert.payload_ciphertext,
    recipients: listAlertRecipients(alert.id),
    requiredRole: alert.tag.replace(/^hosp:/, ""),
    yourRoles: ctx.roles,
  });
});

export const DELETE = withAuth(
  async (req, ctx, params) => {
    const alert = getAlert(params.id);

    if (!alert) {
      return NextResponse.json({ error: "Alert not found" }, { status: 404 });
    }

    if (alert.created_by !== ctx.username) {
      logAccess({
        username: ctx.username,
        action: "delete-alert",
        resource: alert.id,
        outcome: "denied",
        detail: "only the coordinator who raised the alert may delete it",
      });
      return NextResponse.json(
        { error: "Only the coordinator who raised this alert may delete it" },
        { status: 403 }
      );
    }

    const result = deleteAlertAndAudit(alert.id, ctx.username);
    if (!result) {
      return NextResponse.json({ error: "Alert not found" }, { status: 404 });
    }

    return NextResponse.json({
      ok: true,
      deletedAlertId: alert.id,
      deletedReports: result.deletedReports,
    });
  },
  { requireAnyRole: ["coordinator"] }
);
