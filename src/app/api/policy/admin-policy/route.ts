import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import { loadTideConfig } from "@/lib/tidecloakConfig";

/**
 * Proxy the realm's signed admin policy to the browser.
 *
 * Deploying a Forseti policy requires attaching the realm's own admin policy to the signing
 * request, and that policy lives behind an admin-token endpoint the browser cannot call. So this
 * route fetches it with a master-admin token and forwards the bytes.
 *
 * Three things here are easy to get wrong and each costs a wasted enclave approval:
 *
 *  1. The endpoint. `GET /admin/realms/{realm}/tide-admin/realm-policy` looks right and returns
 *     `{status: "none"}` even when the policy exists — it only reports status. The signed bytes
 *     live in `GET /admin/realms/{realm}/iga/role-policies`, in each record's `policy` field.
 *
 *  2. The record. The realm admin policy is named `tide-realm-admin`, NOT `admin-policy`. Code that
 *     looks for the wrong name and falls back to `policies[0]` works today only because there is
 *     exactly one record; add a second and it silently deploys under the wrong authority. We match
 *     by name and fail loudly.
 *
 *  3. The encoding. We forward the base64 as TEXT and let the browser decode it. Decoding and
 *     re-encoding server-side invites the classic error of passing base64 characters as byte
 *     values, which the ORKs report as "Index out of range" because the policy structure is
 *     garbage.
 */

export const GET = withAuth(
  async () => {
    const config = loadTideConfig();
    const authServerUrl = config["auth-server-url"].replace(/\/+$/, "");
    const realm = config.realm;

    const adminUser = process.env.KC_BOOTSTRAP_ADMIN_USERNAME || "admin";
    const adminPassword = process.env.KC_BOOTSTRAP_ADMIN_PASSWORD;

    if (!adminPassword) {
      return NextResponse.json(
        {
          error: "KC_BOOTSTRAP_ADMIN_PASSWORD is not set on the server",
          hint: "It lives in .env and is needed to read the realm's signed admin policy.",
        },
        { status: 503 }
      );
    }

    // Master-admin tokens live about 60 seconds, so mint on demand rather than caching.
    const tokenRes = await fetch(`${authServerUrl}/realms/master/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: adminUser,
        password: adminPassword,
        grant_type: "password",
        client_id: "admin-cli",
      }),
    });

    if (!tokenRes.ok) {
      return NextResponse.json(
        { error: "Could not obtain a TideCloak admin token", status: tokenRes.status },
        { status: 502 }
      );
    }
    const { access_token: adminToken } = (await tokenRes.json()) as { access_token: string };

    const rpRes = await fetch(`${authServerUrl}/admin/realms/${realm}/iga/role-policies`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });

    if (!rpRes.ok) {
      return NextResponse.json(
        { error: "Could not read /iga/role-policies", status: rpRes.status },
        { status: 502 }
      );
    }

    const policies = (await rpRes.json()) as { name?: string; policy?: string }[];

    if (!Array.isArray(policies) || policies.length === 0) {
      // An empty array is not a broken endpoint. The tide-realm-admin policy is created as part of
      // granting that role, so before the grant this legitimately returns [].
      return NextResponse.json(
        {
          error: "No role policies exist yet",
          detail:
            "The tide-realm-admin policy is created when that role is granted. " +
            "Enrol hospital-admin, then run `npm run finalize`.",
        },
        { status: 409 }
      );
    }

    const matches = policies.filter((p) => p.name === "tide-realm-admin");
    if (matches.length !== 1) {
      return NextResponse.json(
        {
          error: `Expected exactly one policy named "tide-realm-admin", found ${matches.length}`,
          detail:
            "Refusing to guess. Falling back to the first record would deploy under the wrong authority.",
          available: policies.map((p) => p.name),
        },
        { status: 409 }
      );
    }

    const policyB64 = matches[0].policy;
    if (!policyB64) {
      return NextResponse.json(
        { error: "The tide-realm-admin policy record has an empty `policy` field" },
        { status: 409 }
      );
    }

    // Forward as text. The browser decodes.
    return NextResponse.json(
      { adminPolicyB64: policyB64, name: "tide-realm-admin" },
      { headers: { "Cache-Control": "no-store" } }
    );
  },
  { requireAnyRole: ["hospital-admin"] }
);
