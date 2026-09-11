/** Read-only diagnostic: what is the realm's ACTUAL state? */
import { loadEnv, adminFetch, findUser, listRealmRoles, getClientUuid } from "./lib/tidecloak.mjs";

const cfg = loadEnv();

console.log("=== realm flags ===");
const realm = await adminFetch(cfg, `/admin/realms/${cfg.realm}`);
console.log("isIGAEnabled :", realm.body?.attributes?.isIGAEnabled);
console.log("iga.attestor :", realm.body?.attributes?.["iga.attestor"]);

console.log("\n=== change requests (all statuses) ===");
for (const status of ["PENDING", "APPROVED", "DENIED", "CANCELLED"]) {
  const r = await adminFetch(cfg, `/admin/realms/${cfg.realm}/iga/change-requests?status=${status}`);
  const arr = Array.isArray(r.body) ? r.body : r.body && typeof r.body === "object" ? Object.values(r.body) : [];
  console.log(`${status}: ${arr.length}`);
  for (const cr of arr.slice(0, 12)) {
    console.log(
      `   ${cr.id}  ${cr.actionType ?? "?"}  ${cr.entityType ?? "?"}  ready=${cr.readyToCommit}  ` +
        `${cr.entityName ?? cr.roleName ?? cr.userName ?? ""}`
    );
  }
}

console.log("\n=== realm roles ===");
const roles = await listRealmRoles(cfg);
console.log(roles.map((r) => r.name).sort().join(", "));

console.log("\n=== user role mappings ===");
for (const u of ["coordinator", "nurse-a", "doctor-a", "doctor-b", "hospital-admin"]) {
  const user = await findUser(cfg, u);
  if (!user) {
    console.log(`${u}: NOT FOUND`);
    continue;
  }
  const rm = await adminFetch(cfg, `/admin/realms/${cfg.realm}/users/${user.id}/role-mappings/realm`);
  const names = (rm.body || []).map((r) => r.name).sort();
  const comp = await adminFetch(cfg, `/admin/realms/${cfg.realm}/users/${user.id}/role-mappings/realm/composite`);
  const compNames = (comp.body || []).map((r) => r.name).sort();
  console.log(`${u}:`);
  console.log(`   direct    : ${names.join(", ") || "(none)"}`);
  console.log(`   effective : ${compNames.join(", ") || "(none)"}`);
  console.log(`   tideUserKey: ${user.attributes?.tideUserKey ? "LINKED" : "not linked"}`);
}

console.log("\n=== reproduce a single role grant, with the response body ===");
const target = await findUser(cfg, "doctor-b");
const roleByName = new Map(roles.map((r) => [r.name, r]));
const one = roleByName.get("clinical-staff");
const res = await adminFetch(
  cfg,
  `/admin/realms/${cfg.realm}/users/${target.id}/role-mappings/realm`,
  { method: "POST", json: [{ id: one.id, name: one.name }], raw: true }
);
console.log(`POST role-mappings/realm [clinical-staff] -> ${res.status}`);
console.log(`body: ${res.text?.slice(0, 900)}`);

console.log("\n=== tide-realm-admin grant, with the response body ===");
const rmUuid = await getClientUuid(cfg, "realm-management");
const roleRes = await adminFetch(cfg, `/admin/realms/${cfg.realm}/clients/${rmUuid}/roles/tide-realm-admin`);
console.log(`lookup tide-realm-admin -> ${roleRes.status}`);
const admin = await findUser(cfg, "hospital-admin");
const g = await adminFetch(
  cfg,
  `/admin/realms/${cfg.realm}/users/${admin.id}/role-mappings/clients/${rmUuid}`,
  { method: "POST", json: [roleRes.body], raw: true }
);
console.log(`POST role-mappings/clients -> ${g.status}`);
console.log(`body: ${g.text?.slice(0, 900)}`);
