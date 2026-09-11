import { NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { withAuth } from "@/lib/api-auth";
import { loadTideConfig } from "@/lib/tidecloakConfig";

/**
 * The Forseti contract source, its identity hash, and the REST upload.
 *
 * GET  -> { source, contractId, ... }   contractId is UPPERCASE SHA-512 hex of the exact source
 * POST -> uploads the source into the realm's contract library
 *
 * Two hashes are involved and mixing them up is a documented trap:
 *
 *   - The upload response returns `contractHash`, which is SHA-256 and is only TideCloak's internal
 *     dedup key for the library table.
 *   - A policy's `contractId` is SHA-512 hex, and that is what the ORKs match against.
 *
 * So we compute the SHA-512 ourselves and never read the id out of the upload response.
 *
 * It must also be UPPERCASE. The ORKs compare it as a case-sensitive string and use
 * Convert.ToHexString (uppercase), while Node's digest("hex") is lowercase. Getting this wrong
 * produces "Policy refers to wrong contract" quoting two values that differ only in case.
 *
 * Because the id is a hash of the exact source, ANY edit to the contract file — even a comment —
 * invalidates an already-deployed policy. That is why GET returns the live hash: the setup page
 * compares it against the deployed policy's stored contractId and warns on drift.
 */

const CONTRACT_PATH = resolve(process.cwd(), "forseti", "HospitalAccessPolicy.cs");

function readContract() {
  const source = readFileSync(CONTRACT_PATH, "utf8");
  const contractId = createHash("sha512").update(source, "utf8").digest("hex").toUpperCase();

  // Assert the shape before it leaves the endpoint, so a malformed id fails here rather than on
  // the ORKs after an enclave approval has been spent.
  if (!/^[0-9A-F]{128}$/.test(contractId)) {
    throw new Error(`Computed contractId has the wrong shape: ${contractId.slice(0, 32)}…`);
  }
  return { source, contractId };
}

export const GET = withAuth(
  async () => {
    const { source, contractId } = readContract();
    const config = loadTideConfig();

    return NextResponse.json(
      {
        source,
        contractId,
        // A Policy's keyId IS the vendorId. Named explicitly because "keyId" invites guessing.
        keyId: config.vendorId,
        sourceBytes: Buffer.byteLength(source, "utf8"),
        params: {
          EncryptRole: "clinical-staff",
          TagPrefix: "hosp:",
        },
      },
      { headers: { "Cache-Control": "no-store" } }
    );
  },
  { requireAnyRole: ["hospital-admin"] }
);

export const POST = withAuth(
  async () => {
    const { source, contractId } = readContract();
    const config = loadTideConfig();
    const authServerUrl = config["auth-server-url"].replace(/\/+$/, "");
    const realm = config.realm;

    const adminPassword = process.env.KC_BOOTSTRAP_ADMIN_PASSWORD;
    if (!adminPassword) {
      return NextResponse.json(
        { error: "KC_BOOTSTRAP_ADMIN_PASSWORD is not set on the server" },
        { status: 503 }
      );
    }

    const tokenRes = await fetch(`${authServerUrl}/realms/master/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: process.env.KC_BOOTSTRAP_ADMIN_USERNAME || "admin",
        password: adminPassword,
        grant_type: "password",
        client_id: "admin-cli",
      }),
    });
    if (!tokenRes.ok) {
      return NextResponse.json({ error: "Could not obtain an admin token" }, { status: 502 });
    }
    const { access_token: adminToken } = (await tokenRes.json()) as { access_token: string };

    // Uploading the contract needs no enclave and no browser — this half IS scriptable. Only the
    // policy SIGNATURE needs a human.
    const upRes = await fetch(`${authServerUrl}/admin/realms/${realm}/iga/forseti-contracts`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ contractCode: source, name: "HospitalAccessPolicy" }),
    });

    const text = await upRes.text();

    if (!upRes.ok) {
      return NextResponse.json(
        {
          error: "Contract upload failed",
          status: upRes.status,
          detail: text.slice(0, 600),
          hint:
            upRes.status === 404
              ? "The /iga/forseti-contracts endpoint is absent. Check the TideCloak version."
              : undefined,
        },
        { status: 502 }
      );
    }

    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }

    return NextResponse.json({
      ok: true,
      // OUR id, computed as SHA-512 uppercase. Never the response's contractHash (SHA-256).
      contractId,
      uploadResponse: parsed,
      note:
        "Uploaded to the realm contract library. The policy still needs a VVK threshold signature, " +
        "which requires a human approval in the Tide enclave.",
    });
  },
  { requireAnyRole: ["hospital-admin"] }
);
