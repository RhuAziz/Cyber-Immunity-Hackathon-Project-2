"use client";

import { IAMService } from "@tidecloak/js";

/**
 * Browser-side encryption for alerts and patient reports.
 *
 * THIS IS THE MOST IMPORTANT FILE TO GET RIGHT, and the mistake is easy to make.
 *
 * Tide has two encryption models and they are not interchangeable:
 *
 *   Self-encryption      doEncrypt(data)                  -> only the ENCRYPTING USER can decrypt
 *   Policy-governed VVK  doEncrypt(data, signedPolicyBytes) -> anyone whose doken satisfies the
 *                                                             Forseti contract can decrypt
 *
 * We need the second one: a coordinator encrypts an alert that six other staff read, and a nurse
 * encrypts a report that a doctor reads. Self-encryption would make each record readable only by
 * whoever wrote it, which would look like working encryption right up until a second person tried
 * to read something.
 *
 * WHY WE DO NOT USE THE `useTideCloak()` HOOK FOR THIS
 *
 * The hook exposes `doEncrypt`/`doDecrypt` and they are the obvious thing to reach for. They are
 * the WRONG thing. Verified against the installed @tidecloak/react 0.14.20:
 *
 *     doEncrypt: async (data) => { ... const result = await IAMService.doEncrypt(data); ... }
 *
 * One argument. The policy is dropped on the floor. There is no error and no warning — you get
 * self-encrypted ciphertext that the intended readers cannot open. So we call IAMService directly
 * with the policy bytes.
 *
 * This is also why nothing here runs on the server. Plaintext must exist only in the browser; a
 * server-side decrypt path would defeat the entire property we are demonstrating.
 */

/** Namespace prefix the Forseti contract requires on every tag. Must match TagPrefix in the policy. */
export const TAG_PREFIX = "hosp:";

/**
 * Build a ciphertext tag from a realm role name.
 *
 * The contract strips TAG_PREFIX and demands the remainder as a realm role, so the tag IS the
 * access rule: `hosp:careteam-patient-1` is readable exactly by holders of `careteam-patient-1`.
 */
export function tagForRole(roleName: string): string {
  return `${TAG_PREFIX}${roleName}`;
}

/** Recover the role a tag requires. Useful for explaining a refusal in the UI. */
export function roleForTag(tag: string): string {
  return tag.startsWith(TAG_PREFIX) ? tag.slice(TAG_PREFIX.length) : tag;
}

export class PolicyMissingError extends Error {
  constructor() {
    super(
      "No signed Forseti policy is deployed. Visit /setup to deploy the contract and sign the policy."
    );
    this.name = "PolicyMissingError";
  }
}

export class DecryptDeniedError extends Error {
  requiredRole: string;
  constructor(requiredRole: string, detail: string) {
    super(detail);
    this.name = "DecryptDeniedError";
    this.requiredRole = requiredRole;
  }
}

/* ------------------------------------------------------------------ *
 * Signed policy bytes
 * ------------------------------------------------------------------ */

let policyCache: Uint8Array | null = null;

/**
 * Fetch the signed policy bytes from our API.
 *
 * These are not a secret. The policy is a public authorisation rule carrying a VVK threshold
 * signature; the ORKs verify that signature before honouring it. Holding the bytes grants nothing —
 * you still need a doken with the right role.
 */
export async function loadPolicyBytes(
  secureFetch: (url: string, init?: RequestInit) => Promise<Response>
): Promise<Uint8Array> {
  if (policyCache) return policyCache;

  const res = await secureFetch(absoluteUrl("/api/policy"));
  if (res.status === 404) throw new PolicyMissingError();
  if (!res.ok) throw new Error(`Could not load the crypto policy (${res.status})`);

  const json = (await res.json()) as { policyB64?: string };
  if (!json.policyB64) throw new PolicyMissingError();

  policyCache = base64ToBytes(json.policyB64);
  return policyCache;
}

export function clearPolicyCache() {
  policyCache = null;
}

/* ------------------------------------------------------------------ *
 * Encrypt / decrypt
 * ------------------------------------------------------------------ */

/**
 * Encrypt a JSON payload under the hospital policy.
 *
 * The ORKs run our Forseti contract before agreeing. For the encrypt direction the contract
 * requires the caller's doken to carry `clinical-staff`, so a non-clinical account — the hospital
 * administrator, for instance — cannot produce ciphertext under this policy at all.
 */
export async function encryptPayload(
  payload: unknown,
  roleName: string,
  policyBytes: Uint8Array
): Promise<{ ciphertext: string; tag: string }> {
  const tag = tagForRole(roleName);
  const plaintext = JSON.stringify(payload);

  // A string input returns a base64 string, which is what we store.
  const [ciphertext] = await IAMService.doEncrypt([{ data: plaintext, tags: [tag] }], policyBytes);

  if (typeof ciphertext !== "string") {
    throw new Error("Expected a base64 string envelope back from doEncrypt");
  }
  return { ciphertext, tag };
}

/**
 * Decrypt a payload. Throws DecryptDeniedError when the ORK network refuses.
 *
 * A refusal here is not our application saying no. It is a majority of independent ORK nodes each
 * running the contract against the caller's doken and declining to participate. No amount of
 * editing our database changes the outcome.
 */
export async function decryptPayload<T = unknown>(
  ciphertext: string,
  tag: string,
  policyBytes: Uint8Array
): Promise<T> {
  try {
    const [plaintext] = await IAMService.doDecrypt(
      [{ encrypted: ciphertext, tags: [tag] }],
      policyBytes
    );

    if (typeof plaintext !== "string") {
      throw new Error("Expected a string back from doDecrypt");
    }
    return JSON.parse(plaintext) as T;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    // Contract denials arrive as opaque strings from the ORKs. Recognise the shapes that mean
    // "the network refused you" and present them as an authorisation outcome rather than a crash,
    // since for this app a refusal is a correct and expected result.
    if (
      /deny|denied|not authori|missing role|does not have|role|threshold|voucher|policy/i.test(
        message
      )
    ) {
      throw new DecryptDeniedError(roleForTag(tag), message);
    }
    throw err;
  }
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

/**
 * secureFetch requires an ABSOLUTE url. Given a relative path it throws
 * "Failed to construct 'URL': Invalid URL" from inside the SDK, before any request is made,
 * because it derives the DPoP `htu` with a bare `new URL()` and no base.
 */
export function absoluteUrl(path: string): string {
  return new URL(path, window.location.origin).href;
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
