import path from "path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Next.js 16 defaults to Turbopack, but the @tidecloak/* packages need the two
  // webpack workarounds below, so package.json runs `next dev/build --webpack`.
  webpack: (config) => {
    // Workaround 1: @tidecloak/js has incomplete re-exports from heimdall-tide.
    // Without this, webpack hard-errors on the missing re-exports.
    config.module.strictExportPresence = false;

    // Workaround 2: @tidecloak/react's CJS dist contains ESM `import` syntax, so when
    // @tidecloak/nextjs does require("@tidecloak/react") webpack follows the CJS path
    // and fails. Force resolution to the ESM dist. Must be path.resolve, not
    // require.resolve (which throws ERR_PACKAGE_PATH_NOT_EXPORTED).
    config.resolve.alias = {
      ...config.resolve.alias,
      "@tidecloak/react": path.resolve(
        __dirname,
        "node_modules/@tidecloak/react/dist/esm/index.js"
      ),
    };

    return config;
  },

  async rewrites() {
    // The Tide enclave requests the DPoP relay at
    //   /tide_dpop/iss/<hex-issuer>/aud/<hex-client>/tide_dpop_auth.html
    // because the relay page parses iss/aud out of its OWN url path. So this must be a
    // WILDCARD rewrite (:path*) to a STATIC file — an exact-path rewrite 404s, and a
    // route handler gets Next's own hash-based CSP injected, which blocks the inline script.
    return [{ source: "/tide_dpop/:path*", destination: "/tide_dpop_auth.html" }];
  },

  async headers() {
    return [
      {
        // I-06: frame-src '*' is required for the SWE iframe, because users can re-home
        // their session to any ORK they trust — there is no fixed domain list.
        // Do NOT add frame-ancestors 'self': it reads as routine hardening but breaks the
        // enclave, which frames our own origin for silent SSO and the approval popup.
        source: "/:path*",
        headers: [{ key: "Content-Security-Policy", value: "frame-src 'self' *" }],
      },
      {
        // MUST come AFTER the catch-all: for a given header key the LAST matching rule
        // wins. Path specificity does not decide it.
        // Allow-CSP-From is CSP Embedded Enforcement — the embedder pins a script hash on
        // the iframe, and omitting this opt-in is exactly what refuses the frame.
        source: "/tide_dpop/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value: "default-src 'self'; script-src 'unsafe-inline'",
          },
          { key: "Allow-CSP-From", value: "*" },
        ],
      },
    ];
  },
};

export default nextConfig;
