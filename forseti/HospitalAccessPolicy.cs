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
//   DECRYPT  tags support two formats:
//
//            hosp:<role>
//              The caller must hold the realm role named after the prefix. For example,
//              hosp:careteam-patient-1 requires careteam-patient-1.
//
//            hosp:user:<vuid>
//              The caller's doken VUID must exactly match the VUID named by the tag, and
//              the caller must also hold clinical-staff. This allows one named enrolled
//              user to be selected for one ciphertext without changing the team-tag rules.
//
//   Examples:
//
//              hosp:response-team-infection-control
//                -> requires realm role response-team-infection-control
//              hosp:user:f89a7e5d1103476596c4c9e51afabd4d003224c002ff09a46279c2c259cd7426
//                -> requires that exact doken VUID plus clinical-staff
//
// The application database may store the tag and recipient list, but the ORKs enforce the
// cryptographic decision from the ciphertext tag and the caller's doken.
//
// WHY THE TAG CHECK IS SAFE
//
// The tag is bound into the ciphertext at encryption time. A caller cannot make a ciphertext
// readable by changing the tag on a decrypt request: the supplied tag must match the ciphertext
// envelope, and the ORKs then evaluate that tag against the caller's doken.
//
// Role tags delegate access to everyone holding the named realm role. Identity tags narrow access
// to the doken VUID named by the tag, while also requiring clinical-staff. The application database
// may store usernames and recipient lists for discovery, but changing those rows cannot change the
// ORK decision.
//
// SCOPE LIMIT
//
// Identity tags bind one ciphertext to one VUID, but they are not a separate grant or revocation
// system. Anyone whose current doken has the matching VUID and clinical-staff can decrypt. The
// contract does not prove that a coordinator intentionally granted the VUID; that would require a
// separate signed capability/grant policy. Existing role tags retain their role-level granularity.

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
    private bool _isIdentityTag;
    private string _requiredVuid;
    private bool _dataValidated;

    public PolicyDecision ValidateData(DataContext ctx)
    {
        // Reset per-request state before parsing. ValidateExecutor must never reuse a tag or
        // identity captured by an earlier request.
        _tags.Clear();
        _isIdentityTag = false;
        _requiredVuid = null;
        _dataValidated = false;

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

        string value = tag.Substring(TagPrefix.Length);
        if (string.IsNullOrEmpty(value))
        {
            return PolicyDecision.Deny("Tag value is empty");
        }

        if (value.StartsWith("user:", StringComparison.Ordinal))
        {
            _isIdentityTag = true;
            _requiredVuid = value.Substring("user:".Length);
            if (string.IsNullOrEmpty(_requiredVuid) || _requiredVuid.IndexOf(':') >= 0)
            {
                return PolicyDecision.Deny("Identity tag must contain exactly one non-empty VUID");
            }
        }
        else
        {
            // Existing role tags are exactly hosp:<role>: one non-empty role value and no
            // additional identity fields. Normal team role names continue to work unchanged.
            if (value.IndexOf(':') >= 0)
            {
                return PolicyDecision.Deny("Role tag contains unexpected fields");
            }
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
            // Encryption: must be clinical staff. The tag may name a different user who will
            // decrypt later, so identity tags are checked against the executor only on decrypt.
            return Decision
                .RequireNotExpired(executor)
                .RequireRole(executor, EncryptRole);
        }

        if (_isIdentityTag)
        {
            // Identity-tag decryption requires both the current clinical-staff role and an exact
            // match between the tag's VUID and the caller's Tide doken VUID.
            return Decision
                .RequireNotExpired(executor)
                .RequireRole(executor, EncryptRole)
                .Require(_requiredVuid == executor.UserId, "Caller VUID does not match the identity tag");
        }

        // Existing role-tag decryption remains role-based exactly as before.
        string requiredRole = _tags[0].Substring(TagPrefix.Length);

        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, requiredRole);
    }
}
