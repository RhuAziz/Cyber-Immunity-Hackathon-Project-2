"use client";

import { useCallback, useEffect, useState } from "react";
import { useTideCloak } from "@tidecloak/nextjs";
import { IAMService } from "@tidecloak/js";
import { absoluteUrl, base64ToBytes, bytesToBase64, clearPolicyCache } from "@/lib/crypto-client";
import { authenticatedFetch } from "@/lib/authenticated-fetch";

/**
 * Deploy the Forseti contract and sign the encryption policy.
 *
 * This is a one-time administrative setup step, and it CANNOT be fully scripted. The final
 * signature requires a human approval in the Tide enclave popup — deliberately, because a policy
 * that governs who may decrypt patient records must not be deployable by a stolen automation
 * credential. That is the security property, not an inconvenience.
 *
 * The signing flow has a specific shape and each deviation costs a full approval cycle, because
 * failures land at the threshold-signature stage AFTER the operator has already approved:
 *
 *   1. PolicySignRequest.New(policy).addForsetiContractToUpload(source)
 *        Owns the three-level contract transport. Hand-rolling it and dropping the outer "forseti"
 *        level makes every ORK reject with `Unknown contract type ''` — an EMPTY type, because the
 *        ORK read position 0 of a structure one level too shallow.
 *   2. tc.createTideRequest(...)
 *   3. tc.requestTideOperatorApproval(...)      <- the human step
 *   4. BaseTideRequest.decode(approved).addPolicy(adminPolicyBytes)
 *        The admin policy is attached AFTER approval, to the approved request. Attaching it during
 *        construction makes createTideRequest fail immediately.
 *   5. tc.executeSignRequest(encoded, true)     <- waitForAll MUST be true
 *   6. policy.signature = sig; store policy.toBytes()
 *        Store the POLICY bytes, not the request encoding, and not the bare signature.
 */

type Phase = "idle" | "running" | "done" | "error";

interface Step {
  label: string;
  status: "pending" | "active" | "ok" | "fail";
  detail?: string;
}

const STEP_LABELS = [
  "Load contract source and compute its SHA-512 identity",
  "Upload the contract to the realm library (no enclave needed)",
  "Fetch the realm's signed tide-realm-admin policy",
  "Build the Policy object",
  "Initialise the Tide request",
  "Await your approval in the Tide enclave",
  "Attach the admin policy to the approved request",
  "Collect the VVK threshold signature from the ORK network",
  "Store the signed policy",
];

export default function SetupPage() {
  const { authenticated, isInitializing, login, hasRealmRole, secureFetch, getToken, token } = useTideCloak();
  const api = useCallback(
    (url: string, init?: RequestInit) => authenticatedFetch(secureFetch, getToken, url, init),
    [getToken, secureFetch]
  );

  const [phase, setPhase] = useState<Phase>("idle");
  const [steps, setSteps] = useState<Step[]>(
    STEP_LABELS.map((label) => ({ label, status: "pending" }))
  );
  const [error, setError] = useState<string | null>(null);
  const [deployed, setDeployed] = useState<{
    contractId: string;
    deployedBy: string;
    deployedAt: string;
  } | null>(null);
  const [liveContractId, setLiveContractId] = useState<string | null>(null);

  const setStep = (i: number, status: Step["status"], detail?: string) =>
    setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, status, detail } : s)));

  /* ---------------- current state ---------------- */
  const refresh = useCallback(async () => {
    if (!authenticated) return;
    try {
      const res = await api(absoluteUrl("/api/policy"));
      if (res.ok) {
        const j = await res.json();
        setDeployed({ contractId: j.contractId, deployedBy: j.deployedBy, deployedAt: j.deployedAt });
      } else {
        setDeployed(null);
      }
    } catch {
      setDeployed(null);
    }

    if (hasRealmRole("hospital-admin")) {
      try {
        const res = await api(absoluteUrl("/api/policy/contract"));
        if (res.ok) setLiveContractId((await res.json()).contractId);
      } catch {
        /* non-fatal */
      }
    }
  }, [api, authenticated, hasRealmRole]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /* ---------------- deploy ---------------- */
  const deploy = async () => {
    setPhase("running");
    setError(null);
    setSteps(STEP_LABELS.map((label) => ({ label, status: "pending" })));

    try {
      /* 1. contract source + identity */
      setStep(0, "active");
      const cRes = await api(absoluteUrl("/api/policy/contract"));
      if (!cRes.ok) throw new Error(`Could not load the contract: ${await cRes.text()}`);
      const { source, contractId, keyId, params } = await cRes.json();

      if (!/^[0-9A-F]{128}$/.test(contractId)) {
        throw new Error(`contractId must be 128 uppercase hex chars, got: ${contractId?.slice(0, 40)}`);
      }
      setStep(0, "ok", `contractId ${contractId.slice(0, 16)}… (${source.length} chars of C#)`);

      /* 2. upload */
      setStep(1, "active");
      const upRes = await api(absoluteUrl("/api/policy/contract"), { method: "POST" });
      if (!upRes.ok) throw new Error(`Contract upload failed: ${await upRes.text()}`);
      setStep(1, "ok", "in the realm contract library");

      /* 3. admin policy */
      setStep(2, "active");
      const apRes = await api(absoluteUrl("/api/policy/admin-policy"));
      if (!apRes.ok) {
        const t = await apRes.text();
        throw new Error(
          `Could not read the tide-realm-admin policy: ${t}\n\n` +
            "If this says no role policies exist, hospital-admin has not been granted " +
            "tide-realm-admin yet. Enrol that user, then run `npm run finalize`."
        );
      }
      const { adminPolicyB64 } = await apRes.json();
      // Decode in the browser. Decoding and re-encoding server-side is how people end up passing
      // base64 CHARACTERS as byte values, which the ORKs report as "Index out of range".
      const adminPolicyBytes = base64ToBytes(adminPolicyB64);
      setStep(2, "ok", `${adminPolicyBytes.length} bytes`);

      /* 4. build the Policy */
      setStep(3, "active");
      // Models comes from @tidecloak/js. Importing it from @tidecloak/nextjs yields `undefined`
      // and fails with "Cannot destructure property 'Policy' of 'Models'".
      const tideJs = await import("@tidecloak/js");
      const Models = (tideJs as unknown as { Models: Record<string, unknown> }).Models;
      if (!Models) throw new Error("Models is undefined — wrong import path for the SDK models");

      // The SDK's own Policy type demands every field on the instance, but we only ever touch
      // toBytes() and signature. There is also no exported PolicyConfig type, and hand-writing one
      // is a documented trap: a type describing the INTENDED shape typechecks clean against a call
      // that cannot work, because the real constructor validates fields sequentially and throws
      // bare strings. So keep the surface minimal and deliberately loose.
      const Policy = Models.Policy as unknown as new (cfg: Record<string, unknown>) => {
        toBytes(): Uint8Array;
        signature: unknown;
        modelIds: string[];
      };
      const ApprovalType = Models.ApprovalType as Record<string, number>;
      const ExecutionType = Models.ExecutionType as Record<string, number>;
      const BaseTideRequest = Models.BaseTideRequest as {
        decode(b: Uint8Array): { addPolicy(p: Uint8Array): void; encode(): Uint8Array };
      };

      const policy = new Policy({
        // Must be exactly "3". The constructor throws a BARE STRING (not an Error) on the first
        // field mismatch, and validates sequentially, so a wrong shape costs one round trip per
        // wrong field.
        version: "3",
        contractId,
        // The key is SINGULAR `modelId` even though the class field is `modelIds`. The plural name
        // is the one visible in editors and logs, so `modelIds:` looks right and is silently
        // ignored, producing "ModelId is not a string" — which does not name the key it wanted.
        //
        // Both registered encryption models are declared because this one policy governs both
        // directions, and the contract branches on ctx.RequestId to apply different rules.
        modelId: ["PolicyEnabledEncryption:1", "PolicyEnabledDecryption:1"],
        // A Policy's keyId IS the vendorId.
        keyId,
        // IMPLICIT: no per-operation approval popup. Clinicians decrypt without a prompt.
        approvalType: ApprovalType.IMPLICIT,
        // PRIVATE: required, or ValidateExecutor never runs and the contract's role check is dead
        // code. Our contract asserts both of these itself and denies if deployed otherwise.
        executionType: ExecutionType.PRIVATE,
        // Pairs, never a plain object.
        params: [
          ["EncryptRole", params.EncryptRole],
          ["TagPrefix", params.TagPrefix],
        ],
      });
      setStep(3, "ok", `IMPLICIT / PRIVATE, params: EncryptRole=${params.EncryptRole}, TagPrefix=${params.TagPrefix}`);

      /* 5. initialise */
      setStep(4, "active");
      // Policy signing methods live on the underlying TideCloak instance, not on IAMService, and
      // not on the React context (which does not expose the approve/execute steps).
      const tc = (IAMService as unknown as { getTideCloakClient(): Record<string, Function> })
        .getTideCloakClient();

      const { PolicySignRequest } = await import("heimdall-tide");
      // PolicySignRequest owns the three-level contract transport. Do not hand-roll it.
      // Cast through unknown: our deliberately-minimal Policy surface is not the SDK's full type.
      const policyRequest = PolicySignRequest.New(
        policy as unknown as Parameters<typeof PolicySignRequest.New>[0]
      ).addForsetiContractToUpload(source);
      const initialized = await tc.createTideRequest(policyRequest.encode());
      setStep(4, "ok");

      /* 6. human approval */
      setStep(5, "active", "A Tide enclave popup should have opened. Approve there.");
      const approvals = await tc.requestTideOperatorApproval([
        { id: "hospital-policy-deploy", request: initialized },
      ]);
      if (approvals?.[0]?.status !== "approved") {
        throw new Error(`Approval was not granted (status: ${approvals?.[0]?.status ?? "unknown"})`);
      }
      setStep(5, "ok", "approved in the enclave");

      /* 7. attach the admin policy AFTER approval */
      setStep(6, "active");
      const approved = BaseTideRequest.decode(approvals[0].request);
      approved.addPolicy(adminPolicyBytes);
      setStep(6, "ok");

      /* 8. threshold signature */
      setStep(7, "active", "Waiting for the ORK network");
      // waitForAll MUST be true.
      const signatures = await tc.executeSignRequest(approved.encode(), true);
      if (!signatures?.[0]) throw new Error("The ORK network returned no signature");
      setStep(7, "ok", `${signatures[0].length}-byte Ed25519 signature`);

      /* 9. store */
      setStep(8, "active");
      policy.signature = signatures[0];
      const signedBytes = policy.toBytes(); // NOT request.encode(), NOT the bare signature

      const saveRes = await api(absoluteUrl("/api/policy"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policyB64: bytesToBase64(signedBytes), contractId }),
      });
      if (!saveRes.ok) throw new Error(`Could not store the policy: ${await saveRes.text()}`);
      setStep(8, "ok", `${signedBytes.length} signed bytes stored`);

      clearPolicyCache();
      setPhase("done");
      await refresh();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setPhase("error");
      setSteps((prev) => {
        const i = prev.findIndex((s) => s.status === "active");
        if (i === -1) return prev;
        return prev.map((s, idx) => (idx === i ? { ...s, status: "fail", detail: msg } : s));
      });
    }
  };

  /* ---------------- render ---------------- */

  if (isInitializing) {
    return (
      <div className="card">
        <h1>Starting…</h1>
      </div>
    );
  }

  if (!authenticated) {
    return (
      <div className="card">
        <h1>Encryption policy</h1>
        <p className="muted">Sign in as the administrator to deploy the Forseti policy.</p>
        <button className="btn" onClick={() => login()}>
          Sign in
        </button>
      </div>
    );
  }

  const isAdmin = hasRealmRole("hospital-admin");
  const contractDrifted = deployed && liveContractId && deployed.contractId !== liveContractId;

  return (
    <>
      <div className="card">
        <h1>Encryption policy</h1>
        <p className="muted">
          One Forseti contract governs every encryption and decryption in this platform. It runs
          inside a sandbox on every ORK in the Tide network, and a majority must independently agree
          before the network will encrypt or decrypt anything.
        </p>

        <h2>What the contract enforces</h2>
        <table>
          <thead>
            <tr>
              <th>Direction</th>
              <th>Requirement</th>
              <th>Effect</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Encrypt</td>
              <td>
                <span className="badge role">clinical-staff</span>
              </td>
              <td>
                The administrator holds no clinical role, so cannot produce ciphertext under this
                policy at all.
              </td>
            </tr>
            <tr>
              <td>Decrypt</td>
              <td>the realm role named by the ciphertext&apos;s own tag</td>
              <td>
                <span className="badge role">hosp:careteam-patient-1</span> is readable only by
                holders of <span className="badge role">careteam-patient-1</span>.
              </td>
            </tr>
          </tbody>
        </table>

        {deployed ? (
          <div className={`notice ${contractDrifted ? "warn" : "ok"}`}>
            <h3>{contractDrifted ? "Policy deployed, but the contract has changed" : "Policy deployed"}</h3>
            <dl className="kv">
              <dt>Contract id</dt>
              <dd className="mono">{deployed.contractId.slice(0, 32)}…</dd>
              <dt>Deployed by</dt>
              <dd>{deployed.deployedBy}</dd>
              <dt>Deployed at</dt>
              <dd>{new Date(deployed.deployedAt).toLocaleString()}</dd>
            </dl>
            {contractDrifted && (
              <p>
                The contract file on disk now hashes to{" "}
                <span className="mono">{liveContractId?.slice(0, 32)}…</span>, which does not match
                the deployed policy. Because the id is a hash of the exact source, any edit — even a
                comment — invalidates the deployment. The ORKs will reject decryption until you
                redeploy.
              </p>
            )}
          </div>
        ) : (
          <div className="notice warn">
            <h3>No policy deployed yet</h3>
            <p>
              Encryption and decryption are unavailable until an administrator completes the steps
              below.
            </p>
          </div>
        )}
      </div>

      {!isAdmin ? (
        <div className="card">
          <div className="notice info">
            <h3>Administrator only</h3>
            <p>
              Deploying the policy requires the <span className="badge role">hospital-admin</span>{" "}
              role. Your roles: {" "}
              {(["coordinator", "doctor", "nurse", "hospital-admin"] as const)
                .filter((r) => hasRealmRole(r))
                .map((r) => (
                  <span key={r} className="badge role">
                    {r}
                  </span>
                ))}
            </p>
          </div>
        </div>
      ) : (
        <div className="card">
          <h2>{deployed ? "Redeploy" : "Deploy"}</h2>
          <div className="notice info">
            <h3>This needs your approval in a popup</h3>
            <p>
              Step 6 opens the Tide enclave, where you approve the deployment. This cannot be
              automated, and that is the point: a stolen automation credential must not be able to
              deploy a policy that decides who reads patient records. Allow popups for this origin.
            </p>
          </div>

          <ol className="step-list">
            {steps.map((s, i) => (
              <li key={i}>
                <span
                  aria-hidden="true"
                  style={{
                    color:
                      s.status === "ok"
                        ? "var(--ok)"
                        : s.status === "fail"
                          ? "var(--danger)"
                          : s.status === "active"
                            ? "var(--accent)"
                            : "var(--muted)",
                  }}
                >
                  {s.status === "ok" ? "✔" : s.status === "fail" ? "✖" : s.status === "active" ? "⟳" : "○"}
                </span>{" "}
                {s.label}
                {s.detail && (
                  <>
                    <br />
                    <span className="muted mono">{s.detail}</span>
                  </>
                )}
              </li>
            ))}
          </ol>

          <div className="btn-row">
            <button className="btn" onClick={deploy} disabled={phase === "running" || !token}>
              {phase === "running" ? "Deploying…" : deployed ? "Redeploy policy" : "Deploy policy"}
            </button>
            <button className="btn secondary" onClick={() => void refresh()}>
              Refresh status
            </button>
          </div>

          {phase === "done" && (
            <div className="notice ok">
              <h3>Deployed</h3>
              <p>
                The policy is signed and stored. Alerts and reports can now be encrypted, and the
                ORK network will enforce the role rules above on every read.
              </p>
            </div>
          )}

          {error && (
            <div className="notice error">
              <h3>Deployment failed</h3>
              <pre>{error}</pre>
              <p className="muted">
                Nothing was stored. Signing failures are safe to retry — but note that each attempt
                that reaches step 6 costs a fresh enclave approval.
              </p>
            </div>
          )}
        </div>
      )}
    </>
  );
}
