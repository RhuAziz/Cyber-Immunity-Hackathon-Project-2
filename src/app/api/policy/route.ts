import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import { getCryptoPolicy, setCryptoPolicy } from "@/lib/db";
import { loadTideConfig } from "@/lib/tidecloakConfig";

/**
 * The signed Forseti policy that governs every encrypt and decrypt in this app.
 *
 * GET  returns the signed policy bytes to any authenticated user.
 * POST stores a newly deployed policy (admin only).
 *
 * The policy is NOT a secret. It is an authorisation rule carrying a VVK threshold signature that
 * the ORKs verify before honouring it. Possessing the bytes grants nothing: decryption still
 * requires a doken with the role the contract demands. Serving it to all authenticated users is
 * necessary, because every client needs it to build a decrypt request.
 */

export const GET = withAuth(async () => {
  const row = getCryptoPolicy();
  if (!row) {
    return NextResponse.json(
      {
        error: "No policy deployed",
        hint: "Visit /setup to deploy the Forseti contract and sign the encryption policy.",
      },
      { status: 404 }
    );
  }

  return NextResponse.json(
    {
      policyB64: row.policy_b64,
      contractId: row.contract_id,
      deployedBy: row.deployed_by,
      deployedAt: row.deployed_at,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
});

export const POST = withAuth(
  async (req, ctx) => {
    const body = (await req.json()) as { policyB64?: string; contractId?: string };

    if (!body.policyB64 || !body.contractId) {
      return NextResponse.json(
        { error: "policyB64 and contractId are both required" },
        { status: 400 }
      );
    }

    // The ORKs compare contractId as a CASE-SENSITIVE string, and they use uppercase hex
    // (Convert.ToHexString) while Node's digest('hex') is lowercase. A lowercase id fails with
    // "Policy refers to wrong contract" quoting two values that differ only in case, which is
    // genuinely confusing to read. Reject it here instead.
    if (!/^[0-9A-F]{128}$/.test(body.contractId)) {
      return NextResponse.json(
        {
          error: "contractId must be 128 uppercase hex characters (SHA-512 of the contract source)",
          detail:
            "Lowercase hex is the common mistake: the ORKs compare case-sensitively and use uppercase.",
          received: `${body.contractId.slice(0, 24)}… (${body.contractId.length} chars)`,
        },
        { status: 400 }
      );
    }

    // Sanity-check that these bytes at least decode, so a failed signing attempt cannot store
    // garbage that later calls would silently fetch and fail on.
    let byteLength = 0;
    try {
      byteLength = Buffer.from(body.policyB64, "base64").length;
    } catch {
      return NextResponse.json({ error: "policyB64 is not valid base64" }, { status: 400 });
    }
    if (byteLength < 64) {
      return NextResponse.json(
        {
          error: "Policy bytes look too short to carry a VVK signature",
          detail: `Decoded to ${byteLength} bytes. An unsigned policy is rejected by the ORKs.`,
        },
        { status: 400 }
      );
    }

    setCryptoPolicy(body.contractId, body.policyB64, ctx.username);

    return NextResponse.json({
      ok: true,
      contractId: body.contractId,
      policyBytes: byteLength,
      deployedBy: ctx.username,
      vendorId: loadTideConfig().vendorId,
    });
  },
  // Deploying a policy that governs who may read patient data is an administrative act.
  { requireAnyRole: ["hospital-admin"] }
);
