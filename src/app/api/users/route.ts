import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import { loadTideConfig } from "@/lib/tidecloakConfig";

/**
 * Staff directory, used by the coordinator to choose alert recipients.
 *
 * Reads from TideCloak rather than keeping a duplicate user table, so role information is always
 * the realm's own view and cannot drift. That matters here: if the app kept its own copy of "who is
 * on the infection-control team", editing that copy would look like it granted access, and the
 * whole point is that it does not.
 */

interface StaffMember {
  username: string;
  name: string;
  roles: string[];
  /** Whether this user could actually DECRYPT ciphertext tagged for the given role. */
  enrolled: boolean;
}

export const GET = withAuth(async (req) => {
  const config = loadTideConfig();
  const authServerUrl = config["auth-server-url"].replace(/\/+$/, "");
  const realm = config.realm;

  const adminUser = process.env.KC_BOOTSTRAP_ADMIN_USERNAME || "admin";
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
      username: adminUser,
      password: adminPassword,
      grant_type: "password",
      client_id: "admin-cli",
    }),
  });

  if (!tokenRes.ok) {
    return NextResponse.json({ error: "Could not obtain an admin token" }, { status: 502 });
  }
  const { access_token: adminToken } = (await tokenRes.json()) as { access_token: string };

  const usersRes = await fetch(`${authServerUrl}/admin/realms/${realm}/users?max=200`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  if (!usersRes.ok) {
    return NextResponse.json({ error: "Could not list realm users" }, { status: 502 });
  }

  const users = (await usersRes.json()) as {
    id: string;
    username: string;
    firstName?: string;
    lastName?: string;
    attributes?: Record<string, string[]>;
  }[];

  const staff: StaffMember[] = [];

  for (const u of users) {
    const rmRes = await fetch(
      `${authServerUrl}/admin/realms/${realm}/users/${u.id}/role-mappings/realm`,
      { headers: { Authorization: `Bearer ${adminToken}` } }
    );
    const roles = rmRes.ok
      ? ((await rmRes.json()) as { name: string }[])
          .map((r) => r.name)
          .filter((n) => !n.startsWith("default-roles-"))
      : [];

    staff.push({
      username: u.username,
      name: [u.firstName, u.lastName].filter(Boolean).join(" ") || u.username,
      roles,
      enrolled: !!u.attributes?.tideUserKey?.[0],
    });
  }

  staff.sort((a, b) => a.username.localeCompare(b.username));

  return NextResponse.json({ staff });
});
