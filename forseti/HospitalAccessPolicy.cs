// Hospital Emergency Platform — Forseti access policy contract.
//
// This C# runs inside a sandboxed VM on EVERY ORK in the Tide network. A majority of ORKs must
// independently agree before the network will encrypt or decrypt. There is no single point of
// bypass: not our application server, not our database, not a hospital administrator, not one
// compromised ORK.
//
// This file is the actual enforcement point for the project's central security claim. The
// application database is only an index of ciphertext; the rules below are what make the
// ciphertext readable or not.
//
// THE MODEL
//
//   ENCRYPT  the caller's doken must carry the realm role named by EncryptRole
//            (we deploy it as "clinical-staff"). Non-clinical accounts — including the
//            hospital administrator — cannot produce ciphertext under this policy at all.
//
//   DECRYPT  the caller's doken must carry the realm role NAMED BY THE CIPHERTEXT'S OWN TAG.
//            The tag is namespaced with TagPrefix; strip the prefix and the remainder is the
//            required realm role. So:
//
//              tag "hosp:careteam-patient-1"              -> requires realm role careteam-patient-1
//              tag "hosp:response-team-infection-control" -> requires realm role
//                                                            response-team-infection-control
//
// WHY DERIVING THE ROLE FROM THE TAG IS SAFE
//
// A caller chooses the tag on a DECRYPT request, so it is fair to ask whether they can choose an
// easier one. They cannot gain anything: the tag is bound into the ciphertext at encryption time
// and the ORKs will only decrypt when the supplied tag matches. Naming a tag whose role you happen
// to hold does not make someone else's differently-tagged ciphertext readable. And a new patient
// needs only a new realm role, not a new contract or a new policy — while creating that role is an
// IGA-governed change requiring quorum approval, which is precisely why it cannot be self-granted
// by writing rows into our SQLite file.
//
// SCOPE LIMIT — STATED HERE BECAUSE THIS IS WHERE A READER WILL LOOK
//
// Enforcement granularity is the ROLE, not the individual record. Everyone holding
// careteam-patient-1 can decrypt every ciphertext tagged for patient 1. Per-record binding is
// possible — the contract would demand proof of a capability naming one specific report — but
// issuing such a capability is itself an IGA-governed change, so it would cost one human enclave
// approval PER REPORT. That is unusable for ordinary clinical work, so we deliberately did not do
// it. Per-record access (which alert went to which six recipients) is enforced by the application
// ACL in SQLite behind server-side JWT verification, and is therefore NOT protected against an
// attacker who can write to that database.
//
// The hook below keeps the stronger option one string away: set ReadCapabilityTemplate to a
// non-empty value and per-record binding can be added without redesigning the policy.

using Ork.Forseti.Sdk;
using Cryptide.Tools;
using Ork.Shared.Models.Contracts;
using System;
using System.Collections.Generic;
using System.Text;

public class Contract : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Realm role required to encrypt under this policy.")]
    public string EncryptRole { get; set; }

    [PolicyParam(Required = true, Description = "Mandatory namespace prefix on every tag. The required realm role is the tag with this prefix removed.")]
    public string TagPrefix { get; set; }

    [PolicyParam(Required = false, Description = "Reserved. Empty disables per-record capability binding; access to a given record is then enforced by the application ACL. See the scope-limit note above.")]
    public string ReadCapabilityTemplate { get; set; }

    // ValidateData sees the request bytes but NOT the doken. ValidateExecutor sees the doken but
    // NOT the bytes — reading ctx.Data there does not compile on the ORK. So the tag is captured
    // here and compared there, and ValidateExecutor refuses outright if this never ran.
    private readonly List<string> _tags = new List<string>();
    private bool _isDecrypt;
    private bool _dataValidated;

    public PolicyDecision ValidateData(DataContext ctx)
    {
        // Refuse to run under a policy shape this contract was not written for. A contract that
        // checks the executor is meaningless if deployed with ExecutionType.PUBLIC, because then
        // ValidateExecutor never runs at all.
        if (ctx.Policy.ExecutionType != ExecutionType.PRIVATE)
        {
            return PolicyDecision.Deny(
                "Policy must be ExecutionType.PRIVATE so the executor's doken is validated");
        }
        if (ctx.Policy.ApprovalType != ApprovalType.IMPLICIT)
        {
            return PolicyDecision.Deny(
                "Policy must be ApprovalType.IMPLICIT; this contract validates the executor, not approvers");
        }

        ReadOnlyMemory<byte> data = ctx.Data;

        // Encrypt and decrypt have DIFFERENT payload layouts and nothing but RequestId says which.
        // Reading the wrong offset silently collects the wrong strings as "tags", producing a
        // contract that allows or denies on garbage. So branch first, and deny anything unexpected.
        if (ctx.RequestId == "PolicyEnabledEncryption:1")
        {
            _isDecrypt = false;

            // Encryption: outer 0 = time, outer 1 = first request, tags from index 2 of the inner.
            if (data.TryGetValue(2, out var _extraEnc))
            {
                return PolicyDecision.Deny("One item per encryption request");
            }
            var firstEnc = data.GetValue(1);
            for (int i = 2; firstEnc.TryGetValue(i, out var tagEnc); i++)
            {
                _tags.Add(Encoding.UTF8.GetString(tagEnc.Span));
            }
        }
        else if (ctx.RequestId == "PolicyEnabledDecryption:1")
        {
            _isDecrypt = true;

            // Decryption: outer 0 = first request, tags from index 3 of the inner. Note the
            // asymmetry with encryption above — it is not a typo.
            if (data.TryGetValue(1, out var _extraDec))
            {
                return PolicyDecision.Deny("One item per decryption request");
            }
            var firstDec = data.GetValue(0);
            for (int i = 3; firstDec.TryGetValue(i, out var tagDec); i++)
            {
                _tags.Add(Encoding.UTF8.GetString(tagDec.Span));
            }
        }
        else
        {
            return PolicyDecision.Deny("This contract handles only encryption and decryption requests");
        }

        if (_tags.Count != 1)
        {
            return PolicyDecision.Deny("Exactly one tag is required per item");
        }

        string tag = _tags[0];
        if (string.IsNullOrEmpty(tag))
        {
            return PolicyDecision.Deny("Tag is empty");
        }
        if (string.IsNullOrEmpty(TagPrefix) || !tag.StartsWith(TagPrefix, StringComparison.Ordinal))
        {
            return PolicyDecision.Deny("Tag is not in the required namespace");
        }
        if (tag.Length <= TagPrefix.Length)
        {
            return PolicyDecision.Deny("Tag carries no role after its prefix");
        }

        _dataValidated = true;
        return PolicyDecision.Allow();
    }

    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        // FAIL CLOSED. If ValidateData did not run, or ran and never set this, the only safe
        // answer is refusal — "the check did not happen" must never read as "the check passed".
        if (!_dataValidated)
        {
            return PolicyDecision.Deny("Data validation did not run; refusing");
        }

        var executor = new DokenDto(ctx.Doken);

        if (!_isDecrypt)
        {
            // Encryption: must be clinical staff. Deliberately NOT the tag role, so a nurse can
            // file a report before the care team is finalised, while still excluding the
            // administrator, who holds no clinical role.
            return Decision
                .RequireNotExpired(executor)
                .RequireRole(executor, EncryptRole);
        }

        // Decryption: the ciphertext's own tag names the realm role required to read it.
        string requiredRole = _tags[0].Substring(TagPrefix.Length);

        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, requiredRole);
    }
}
