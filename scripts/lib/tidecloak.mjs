/**
 * Shared TideCloak admin-API helpers.
 *
 * Written in Node rather than bash/curl/jq (which is what the Tide playbooks use) because this
 * project is developed on Windows, where the only `bash` is WSL's — a different filesystem context
 * that mistranslates Docker bind-mount paths. Node is already a hard dependency of the app, has
 * native fetch, and makes the IGA drain loop far clearer. The endpoint sequence and ordering are
 * unchanged from the playbook.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Minimal .env loader. Does not overwrite variables already present in the environment. */
export function loadEnv() {
  const envPath = resolve(PROJECT_ROOT, ".env");
  if (existsSync(envPath)) {
    for (const rawLine of readFileSync(envPath, "utf8").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      const value = line.slice(eq + 1).trim();
      if (!(key in process.env)) process.env[key] = value;
    }
  }

  const cfg = {
    tidecloakUrl: (process.env.TIDECLOAK_LOCAL_URL || "http://localhost:8080").replace(/\/+$/, ""),
    appUrl: (process.env.CLIENT_APP_URL || "http://localhost:3000").replace(/\/+$/, ""),
    realm: process.env.NEW_REALM_NAME || "hospital",
    clientName: process.env.CLIENT_NAME || "hospital-app",
    adminUser: process.env.KC_BOOTSTRAP_ADMIN_USERNAME || "admin",
    adminPassword: process.env.KC_BOOTSTRAP_ADMIN_PASSWORD || "",
    licenseEmail: process.env.TIDE_LICENSE_EMAIL || "admin@hospital.example",
  };

  // Fail loudly rather than defaulting. A default password is a hardcoded credential
  // with extra steps, and it ships to whoever runs this next (AP-41).
  if (!cfg.adminPassword) {
    throw new Error(
      "KC_BOOTSTRAP_ADMIN_PASSWORD is not set.\n" +
        "Copy .env.example to .env and set a password. Refusing to use a default."
    );
  }
  return cfg;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ *
 * Admin token
 * ------------------------------------------------------------------ */

/**
 * Master-admin tokens live only ~60 seconds, so we mint on demand rather than
 * caching one for the whole script. Every call site re-requests.
 */
export async function getAdminToken(cfg) {
  const body = new URLSearchParams({
    username: cfg.adminUser,
    password: cfg.adminPassword,
    grant_type: "password",
    client_id: "admin-cli",
  });

  const res = await fetch(`${cfg.tidecloakUrl}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) {
    throw new Error(`Failed to get admin token (${res.status}): ${await res.text()}`);
    }
  const json = await res.json();
  if (!json.access_token) throw new Error("Admin token response had no access_token");
  return json.access_token;
}

/* ------------------------------------------------------------------ *
 * Admin API call wrapper
 * ------------------------------------------------------------------ */

/**
 * Perform an admin API request with a freshly minted token.
 *
 * `form` sends application/x-www-form-urlencoded (several Tide vendor endpoints read form
 * parameters, not JSON — sending JSON to those makes the parameter *missing*, and at least one
 * of them fails OPEN when a parameter is absent).
 */
export async function adminFetch(cfg, path, { method = "GET", json, form, raw } = {}) {
  const token = await getAdminToken(cfg);
  const headers = { Authorization: `Bearer ${token}` };
  let body;

  if (json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  } else if (form !== undefined) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(form);
  }

  const url = path.startsWith("http") ? path : `${cfg.tidecloakUrl}${path}`;
  const res = await fetch(url, { method, headers, body });
  const text = await res.text();

  if (raw) return { ok: res.ok, status: res.status, text };

  let parsed = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
  }
  return { ok: res.ok, status: res.status, body: parsed, text };
}

/** adminFetch that throws on a non-2xx. */
export async function adminFetchOk(cfg, path, opts = {}) {
  const res = await adminFetch(cfg, path, opts);
  if (!res.ok) {
    throw new Error(
      `${opts.method || "GET"} ${path} failed (${res.status}): ${res.text?.slice(0, 500)}`
    );
  }
  return res;
}

/* ------------------------------------------------------------------ *
 * IGA change requests
 * ------------------------------------------------------------------ */

/**
 * Authorize then commit every pending IGA change request.
 *
 * THE RULE THAT ALWAYS HOLDS: with IGA enabled, a 2xx from an admin endpoint means
 * ACCEPTED, not APPLIED. A role creation returns 202 and the role does not exist until its
 * change request is committed. So every mutation must be followed by drain() + a read-back
 * assertion. This is the most expensive class of bug in a bootstrap script, because the
 * visible symptom (a "role not found" during role *assignment*) points several stages later
 * than the actual cause.
 *
 * Notes:
 *  - We authorize each CR individually. bulk-authorize with an actionTypeIn filter of
 *    ["CREATE","DELETE"] matches NOTHING and silently authorizes zero CRs with a 200,
 *    because those are not real action-type values (the real ones are CREATE_USER,
 *    GRANT_ROLES, UPDATE_PROTOCOL_MAPPER, ...). Omitting the filter returns 400.
 *  - Committing loops over several passes so dependent CRs become ready (a role must exist
 *    before its assignment can commit).
 *  - During bootstrap the realm is in firstAdmin mode, so authorize signs server-side with no
 *    browser enclave. Once tide-realm-admin is granted the realm flips to multiAdmin and this
 *    stops working (409 MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE) — which is why that grant is last.
 */
export async function drainChangeRequests(cfg, { label = "", passes = 6 } = {}) {
  let authorized = 0;
  let committed = 0;

  const listPending = async () => {
    const res = await adminFetch(cfg, `/admin/realms/${cfg.realm}/iga/change-requests?status=PENDING`);
    if (!res.ok) return [];
    const b = res.body;
    if (Array.isArray(b)) return b;
    // Older docs describe an object keyed by id. Handle both shapes.
    if (b && typeof b === "object") return Object.values(b);
    return [];
  };

  const pending = await listPending();
  for (const cr of pending) {
    const id = cr?.id;
    if (!id) continue;
    const res = await adminFetch(
      cfg,
      `/admin/realms/${cfg.realm}/iga/change-requests/${id}/authorize`,
      { method: "POST", json: {} }
    );
    if (res.ok) authorized++;
    else if (res.status === 409) {
      // Four-eyes re-sign, or the realm has already flipped to multiAdmin.
      console.warn(`    authorize ${id} -> 409 (${String(res.text).slice(0, 120)})`);
    }
  }

  for (let pass = 0; pass < passes; pass++) {
    const ready = (await listPending()).filter((cr) => cr?.readyToCommit === true);
    if (ready.length === 0) break;
    let progressed = false;
    for (const cr of ready) {
      const res = await adminFetch(
        cfg,
        `/admin/realms/${cfg.realm}/iga/change-requests/${cr.id}/commit`,
        { method: "POST" }
      );
      if (res.ok) {
        committed++;
        progressed = true;
      } else if (res.status !== 412) {
        // 412 = quorum unmet, expected while dependencies settle.
        console.warn(`    commit ${cr.id} -> ${res.status} ${String(res.text).slice(0, 120)}`);
      }
    }
    if (!progressed) break;
  }

  const remaining = (await listPending()).length;
  const tag = label ? ` [${label}]` : "";
  console.log(
    `  IGA drain${tag}: authorized ${authorized}, committed ${committed}, ${remaining} still pending`
  );
  return { authorized, committed, remaining };
}

/* ------------------------------------------------------------------ *
 * Convenience lookups
 * ------------------------------------------------------------------ */

export async function getClientUuid(cfg, clientId) {
  const res = await adminFetchOk(cfg, `/admin/realms/${cfg.realm}/clients?clientId=${encodeURIComponent(clientId)}`);
  const uuid = res.body?.[0]?.id;
  if (!uuid) throw new Error(`Client "${clientId}" not found in realm "${cfg.realm}"`);
  return uuid;
}

export async function findUser(cfg, username) {
  const res = await adminFetch(cfg, `/admin/realms/${cfg.realm}/users?username=${encodeURIComponent(username)}&exact=true`);
  if (!res.ok || !Array.isArray(res.body)) return null;
  return res.body[0] || null;
}

export async function listRealmRoles(cfg) {
  const res = await adminFetch(cfg, `/admin/realms/${cfg.realm}/roles?max=200`);
  return res.ok && Array.isArray(res.body) ? res.body : [];
}

/** Generate a Tide enrollment / account-linking URL for a user. */
export async function getEnrollmentLink(cfg, userId, lifespanSeconds = 43200) {
  const res = await adminFetch(
    cfg,
    `/admin/realms/${cfg.realm}/tideAdminResources/get-required-action-link?userId=${userId}&lifespan=${lifespanSeconds}`,
    { method: "POST", json: ["link-tide-account-action"], raw: true }
  );
  if (!res.ok) return null;
  return res.text.trim().replace(/^"|"$/g, "");
}
