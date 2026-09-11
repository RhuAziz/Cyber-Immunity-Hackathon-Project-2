"use client";

import { TideCloakProvider } from "@tidecloak/nextjs";
import tcConfig from "../../data/tidecloak.json";

/**
 * DPoP goes INSIDE the config object.
 *
 * `TideCloakProvider` from @tidecloak/nextjs accepts only `{ config, children }`. Passing
 * `useDPoP` or `initOptions` as sibling JSX props is silently ignored — extra props are dropped
 * rather than rejected, so it looks configured and is not. (The @tidecloak/react provider,
 * `TideCloakContextProvider`, is the one that takes them as separate props. Different component,
 * different shape.)
 *
 * There is also no SDK default for `useDPoP` in this version: omitting it yields plain bearer
 * tokens with no error and no warning. So it has to be set explicitly, which is why this is driven
 * by an env var that `scripts/set-dpop.mjs` keeps in lockstep with the server-side client
 * attribute. Setting only one side does not disable DPoP, it breaks login.
 */
const DPOP_ENABLED = process.env.NEXT_PUBLIC_TIDE_DPOP === "on";

const config = DPOP_ENABLED
  ? { ...tcConfig, useDPoP: { mode: "strict" as const, alg: "ES256" as const } }
  : { ...tcConfig };

export function Providers({ children }: { children: React.ReactNode }) {
  return <TideCloakProvider config={config}>{children}</TideCloakProvider>;
}
