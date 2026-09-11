/**
 * Regenerate Tide enrolment links.
 *
 * Links expire 12 hours after generation. Users who are already enrolled are reported as such and
 * skipped — re-enrolling is not the intent here.
 */

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { PROJECT_ROOT, loadEnv, findUser, getEnrollmentLink } from "./lib/tidecloak.mjs";

const USERS = [
  ["coordinator", "Creates the Ward 7 alert and scopes it to the infection-control response team."],
  ["nurse-a", "Authorised responder and on patient 1's care team. Files the incident report."],
  ["doctor-a", "On patient 1's care team. Can read the protected report."],
  ["doctor-b", "Doctor from another ward. Valid account, no tag roles — the ORKs refuse to decrypt for him."],
  ["hospital-admin", "App/database administrator. Enrol this one FIRST: `npm run finalize` depends on it."],
];

const cfg = loadEnv();
const rows = [];

for (const [username, note] of USERS) {
  const user = await findUser(cfg, username);
  if (!user) {
    console.log(`${username}: NOT FOUND — run \`npm run init\``);
    continue;
  }

  if (user.attributes?.tideUserKey?.[0]) {
    console.log(`${username}: already enrolled`);
    rows.push({ username, note, status: "already enrolled", link: null });
    continue;
  }

  const link = await getEnrollmentLink(cfg, user.id);
  console.log(`${username}: ${link ? "link generated" : "FAILED"}`);
  rows.push({ username, note, status: link ? "pending enrolment" : "link generation failed", link });
}

const out = resolve(PROJECT_ROOT, "tidecloak", "enrollment-links.md");
writeFileSync(
  out,
  [
    "# Tide enrolment links",
    "",
    `Generated ${new Date().toISOString()}. Links expire after 12 hours.`,
    "",
    "Tide has no admin-set passwords. Each user enrols themselves in a browser, which is where",
    "their credential is created — protected by threshold PRISM and never stored as a hash",
    "anywhere. That is why this cannot be seeded from a script.",
    "",
    "**Enrol `hospital-admin` first**: `npm run finalize` cannot grant `tide-realm-admin` until",
    "that user has a linked Tide identity, and Forseti policy deployment depends on that grant.",
    "",
    ...rows.flatMap((r) => [
      `## ${r.username}`,
      "",
      `- Status: **${r.status}**`,
      `- Demo role: ${r.note}`,
      "",
      r.link ? r.link : "_(no link — already enrolled, or generation failed)_",
      "",
    ]),
  ].join("\n"),
  "utf8"
);

console.log(`\nWritten to ${out}`);
