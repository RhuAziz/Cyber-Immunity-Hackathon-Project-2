import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import { createAlert, listAlertsFor, listAlertRecipients, logAccess } from "@/lib/db";
import { randomUUID } from "node:crypto";

/**
 * Alerts.
 *
 * The server never sees alert content. The browser encrypts the whole payload — title,
 * description, ward, emergency type, severity — under the Forseti policy, and posts only the
 * envelope. There is no code path here that could decrypt it.
 */

export const GET = withAuth(async (req, ctx) => {
  const isCoordinator = ctx.roles.includes("coordinator");
  const rows = listAlertsFor(ctx.username, isCoordinator);

  return NextResponse.json({
    alerts: rows.map((a) => ({
      id: a.id,
      createdBy: a.created_by,
      createdAt: a.created_at,
      tag: a.tag,
      ciphertext: a.payload_ciphertext,
      recipients: listAlertRecipients(a.id),
    })),
    // Handy for the UI to explain a refusal before even attempting a decrypt.
    yourRoles: ctx.roles,
  });
});

export const POST = withAuth(
  async (req, ctx) => {
    const body = (await req.json()) as {
      ciphertext?: string;
      tag?: string;
      recipients?: string[];
    };

    if (!body.ciphertext || !body.tag) {
      return NextResponse.json(
        { error: "ciphertext and tag are required" },
        { status: 400 }
      );
    }

    if (!Array.isArray(body.recipients) || body.recipients.length === 0) {
      return NextResponse.json(
        { error: "At least one recipient is required" },
        { status: 400 }
      );
    }

    // Guard against a client that forgot the policy and sent self-encrypted data. Policy-governed
    // envelopes are materially larger than a bare ElGamal blob, and a suspiciously short payload
    // almost always means the policy argument was dropped.
    if (body.ciphertext.length < 64) {
      return NextResponse.json(
        {
          error: "Ciphertext is implausibly short",
          detail:
            "This usually means encryption ran without the signed policy, which produces " +
            "self-encrypted data that only the author can read. Refusing to store it.",
        },
        { status: 400 }
      );
    }

    const alert = createAlert(
      {
        id: randomUUID(),
        created_by: ctx.username,
        tag: body.tag,
        payload_ciphertext: body.ciphertext,
      },
      body.recipients
    );

    logAccess({
      username: ctx.username,
      action: "create-alert",
      resource: alert.id,
      outcome: "allowed",
      detail: `tag=${body.tag} recipients=${body.recipients.join(",")}`,
    });

    return NextResponse.json({ id: alert.id, createdAt: alert.created_at }, { status: 201 });
  },
  // Only a coordinator may raise an alert. Enforced here, server-side — the nav also hides the
  // link, but that is cosmetic.
  { requireAnyRole: ["coordinator"] }
);
