import { NextResponse } from "next/server";
import { withAuth } from "@/lib/api-auth";
import {
  listPatients,
  upsertPatient,
  addCareTeamMember,
  listCareTeam,
  getPatient,
} from "@/lib/db";

/**
 * Patients and their care teams.
 *
 * Even the patient's NAME is a ciphertext envelope. Requirements section 9 makes the reason
 * concrete: for a high-profile patient admitted discreetly, the identity itself is the secret worth
 * stealing, so storing "John Smith" in a readable column would defeat the exercise before any
 * medical detail was involved.
 */

export const GET = withAuth(async (req, ctx) => {
  const patients = listPatients();

  return NextResponse.json({
    patients: patients.map((p) => ({
      id: p.id,
      tag: p.tag,
      ciphertext: p.payload_ciphertext,
      createdAt: p.created_at,
      careTeam: listCareTeam(p.id),
      requiredRole: p.tag.replace(/^hosp:/, ""),
      appAclSaysAuthorised: listCareTeam(p.id).includes(ctx.username),
    })),
    yourRoles: ctx.roles,
  });
});

export const POST = withAuth(
  async (req, ctx) => {
    const body = (await req.json()) as {
      id?: string;
      ciphertext?: string;
      tag?: string;
      careTeam?: string[];
    };

    if (!body.id || !body.ciphertext || !body.tag) {
      return NextResponse.json({ error: "id, ciphertext and tag are required" }, { status: 400 });
    }

    upsertPatient({ id: body.id, payload_ciphertext: body.ciphertext, tag: body.tag });

    for (const member of body.careTeam ?? []) {
      addCareTeamMember(body.id, member);
    }

    return NextResponse.json({
      ok: true,
      id: body.id,
      careTeam: listCareTeam(body.id),
      // Say plainly what this did and did not do, because it is the crux of the whole project.
      note:
        "Care-team rows are the APPLICATION's access control only. They do not grant the " +
        `realm role "${body.tag.replace(/^hosp:/, "")}", which is what the ORK network actually ` +
        "requires to decrypt. Granting that role is an IGA-governed change needing quorum approval.",
    });
  },
  { requireAnyRole: ["coordinator", "doctor", "nurse", "hospital-admin"] }
);

export const PATCH = withAuth(
  async (req) => {
    const body = (await req.json()) as { patientId?: string; addUsername?: string };

    if (!body.patientId || !body.addUsername) {
      return NextResponse.json(
        { error: "patientId and addUsername are required" },
        { status: 400 }
      );
    }
    if (!getPatient(body.patientId)) {
      return NextResponse.json({ error: "Unknown patient" }, { status: 404 });
    }

    addCareTeamMember(body.patientId, body.addUsername);

    return NextResponse.json({
      ok: true,
      careTeam: listCareTeam(body.patientId),
      note:
        "Added to the application's care-team table. This changes what the application believes " +
        "and changes nothing about what the ORK network will decrypt.",
    });
  },
  { requireAnyRole: ["doctor", "coordinator", "hospital-admin"] }
);
