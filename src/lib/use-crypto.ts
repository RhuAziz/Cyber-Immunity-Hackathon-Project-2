"use client";

import { useCallback, useEffect, useState } from "react";
import { useTideCloak } from "@tidecloak/nextjs";
import {
  absoluteUrl,
  decryptPayload,
  encryptPayload,
  loadPolicyBytes,
  DecryptDeniedError,
  PolicyMissingError,
} from "./crypto-client";

/**
 * Shared hook for the pages that read or write protected records.
 *
 * `secureFetch` comes from the hook rather than the static IAMService, because the static copy is
 * not wired to the provider's auth state. Crypto, by contrast, must go through IAMService directly
 * so the policy argument survives — see crypto-client.ts.
 */
export function useCrypto() {
  const { secureFetch, authenticated } = useTideCloak();
  const [policyBytes, setPolicyBytes] = useState<Uint8Array | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // secureFetch needs an ABSOLUTE url; a relative path throws before any request is sent.
  const api = useCallback(
    (path: string, init?: RequestInit) => secureFetch(absoluteUrl(path), init),
    [secureFetch]
  );

  useEffect(() => {
    if (!authenticated) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const bytes = await loadPolicyBytes((url, init) => secureFetch(url, init));
        if (!cancelled) setPolicyBytes(bytes);
      } catch (err) {
        if (!cancelled) {
          setPolicyError(
            err instanceof PolicyMissingError
              ? "No signed encryption policy is deployed yet. An administrator must complete setup at /setup."
              : (err as Error).message
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authenticated, secureFetch]);

  /** Report a decrypt outcome so refusals appear in the audit trail. */
  const report = useCallback(
    async (action: string, resource: string, outcome: "allowed" | "denied", detail?: string) => {
      try {
        await api("/api/audit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action, resource, outcome, detail }),
        });
      } catch {
        /* auditing is best-effort and must never block the user */
      }
    },
    [api]
  );

  const decrypt = useCallback(
    async <T,>(
      ciphertext: string,
      tag: string,
      resourceId: string,
      action = "decrypt"
    ): Promise<{ ok: true; data: T } | { ok: false; deniedRole?: string; message: string }> => {
      if (!policyBytes) {
        return { ok: false, message: policyError ?? "The encryption policy is not loaded yet." };
      }
      try {
        const data = await decryptPayload<T>(ciphertext, tag, policyBytes);
        void report(action, resourceId, "allowed");
        return { ok: true, data };
      } catch (err) {
        if (err instanceof DecryptDeniedError) {
          void report(action, resourceId, "denied", err.message);
          return { ok: false, deniedRole: err.requiredRole, message: err.message };
        }
        void report(action, resourceId, "denied", (err as Error).message);
        return { ok: false, message: (err as Error).message };
      }
    },
    [policyBytes, policyError, report]
  );

  const encrypt = useCallback(
    async (payload: unknown, roleName: string) => {
      if (!policyBytes) {
        throw new Error(policyError ?? "The encryption policy is not loaded yet.");
      }
      return encryptPayload(payload, roleName, policyBytes);
    },
    [policyBytes, policyError]
  );

  return { api, encrypt, decrypt, policyReady: !!policyBytes, policyError, loading };
}
