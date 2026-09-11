import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import { createReport, getPatient, listCareTeam, listAllReports, logAccess } from "@/lib/db";
import { randomUUID } from "node:crypto";

/**
 * Incident reports containing patient information.
 *
 * These are the most sensitive records in the system and the subject of the project's headline
 * demonstration: a hospital administrator who edits the `care_team` table to add themselves still
 * cannot read them.
 *
 * The reason that holds is that the reader's authorisation is not decided here. The ciphertext is
 * tagged `hosp:careteam-patient-1`, and our Forseti contract makes the ORK network demand the realm
 * role `careteam-patient-1` from the caller's doken. Realm roles are IGA-governed — granting one
 * needs quorum approval sealed by threshold signature — so they cannot be awarded by writing a row
 * into SQLite.
 */

export const GET = withAuth(async (req, ctx) => {
  const url = new URL(req.url);
  const patientId = url.searchParams.get("patientId");

  const all = listAllReports();
  const rows = patientId ? all.filter((r) => r.patient_id === patientId) : all;

  // We deliberately return envelopes for reports the caller may not be able to read.
  //
  // That is not an oversight. It makes the demonstration honest and legible: the client can attempt
  // a decrypt and surface the ORK network's actual refusal, rather than the application quietly
  // filtering the row out and claiming credit for a denial it did not enforce.
  return NextResponse.json({
    reports: rows.map((r) => ({
      id: r.id,
      alertId: r.alert_id,
      patientId: r.patient_id,
      filedBy: r.filed_by,
      createdAt: r.created_at,
      tag: r.tag,
      ciphertext: r.payload_ciphertext,
      requiredRole: r.tag.replace(/^hosp:/, ""),
      // The application ACL's opinion, shown alongside so the two layers can be compared.
      appAclSaysAuthorised: listCareTeam(r.patient_id).includes(ctx.username),
    })),
    yourRoles: ctx.roles,
  });
});

export const POST = withAuth(
  async (req, ctx) => {
    const body = (await req.json()) as {
      ciphertext?: string;
      tag?: string;
      patientId?: string;
      alertId?: string | null;
    };

    if (!body.ciphertext || !body.tag || !body.patientId) {
      return NextResponse.json(
        { error: "ciphertext, tag and patientId are required" },
        { status: 400 }
      );
    }

    if (!getPatient(body.patientId)) {
      return NextResponse.json({ error: "Unknown patient" }, { status: 404 });
    }

    if (body.ciphertext.length < 64) {
      return NextResponse.json(
        {
          error: "Ciphertext is implausibly short",
          detail:
            "This usually means encryption ran without the signed policy, producing " +
            "self-encrypted data only the author could read. Refusing to store it.",
        },
        { status: 400 }
      );
    }

    const report = createReport({
      id: randomUUID(),
      alert_id: body.alertId ?? null,
      patient_id: body.patientId,
      filed_by: ctx.username,
      tag: body.tag,
      payload_ciphertext: body.ciphertext,
    });

    logAccess({
      username: ctx.username,
      action: "file-report",
      resource: report.id,
      outcome: "allowed",
      detail: `patient=${body.patientId} tag=${body.tag}`,
    });

    return NextResponse.json({ id: report.id, createdAt: report.created_at }, { status: 201 });
  },
  // Clinical staff file reports. A coordinator co-ordinates; they do not write patient notes.
  { requireAnyRole: ["nurse", "doctor"] }
);
