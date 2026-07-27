import type { NextConfig } from "next";

const nextConfig: NextConfig = {
	// App Router is on by default in Next.js 15
	experimental: {
		// React 19 + Server Components
		reactCompiler: true,
	},
	// Compile the workspace TS verifier so the dashboard runs the SAME public
	// audit verifier client-side (its `/node` entry keeps node:fs out of this bundle).
	transpilePackages: ["@tracelanedev/audit-verifier"],
	// The PGlite E2E harness (`lib/e2e-db.ts`) statically imports `node:fs`/`node:path`
	// (+ drizzle's pglite migrator → `node:crypto`). It is dev/test-only and guarded
	// out at RUNTIME by the `NODE_ENV`/`NEXT_RUNTIME` checks in `instrumentation.ts` —
	// but webpack creates the dynamic-import() chunk at parse time (before dead-code
	// elimination), so those `node:` schemes still enter the prod Cloudflare Worker /
	// Edge build and break it (`UnhandledSchemeError: node:path`). Swap `e2e-db` for a
	// no-op stub in the PROD webpack build so the chunk carries no `node:` imports.
	// (A `resolve.alias` doesn't catch it — Next resolves the `@/` path via its own
	// resolver plugin before webpack alias runs — so match on `beforeResolve`.) Dev
	// uses Turbopack, which ignores this hook, so the harness still loads for L16.
	webpack(config, { dev, webpack }) {
		if (!dev) {
			config.plugins.push(
				new webpack.NormalModuleReplacementPlugin(
					/[\\/]lib[\\/]e2e-db(\.ts)?$/,
					(resource: { request: string }) => {
						resource.request = resource.request.replace(
							/e2e-db(\.ts)?$/,
							"e2e-db.stub",
						);
					},
				),
			);
		}
		return config;
	},
	// Security headers
	async headers() {
		return [
			{
				source: "/(.*)",
				headers: [
					{ key: "X-Frame-Options", value: "DENY" },
					{ key: "X-Content-Type-Options", value: "nosniff" },
					{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
					// HSTS (pre-announce hardening): 2y + subdomains. `preload` is omitted
					// until the header is confirmed on the wire across every subdomain.
					{
						key: "Strict-Transport-Security",
						value: "max-age=63072000; includeSubDomains",
					},
					{
						key: "Content-Security-Policy",
						value: [
							"default-src 'self'",
							"script-src 'self' 'unsafe-eval' 'unsafe-inline'", // 'unsafe-eval' for WebGL shaders; nonce migration is a follow-up
							"style-src 'self' 'unsafe-inline'",
							"img-src 'self' data: blob:",
							"connect-src 'self' wss:",
							"base-uri 'self'",
							// `form-action` is enforced across the ENTIRE redirect chain of a
							// form submission, not just its initial target. The billing
							// "Upgrade to <tier>" form POSTs to same-origin /api/checkout,
							// which 302-redirects to Polar's hosted checkout
							// (https://polar.sh/checkout/…). With `'self'` only, Chrome refuses
							// that cross-origin hop and the button silently dies (console-only
							// CSP violation, no user-visible error). Allow Polar's checkout
							// host (+ subdomains: sandbox.polar.sh, buy.polar.sh) so the
							// redirect completes. (The billing *portal* button is unaffected —
							// it navigates via window.location, which form-action never governs.)
							"form-action 'self' https://polar.sh https://*.polar.sh",
							"frame-ancestors 'none'",
							"object-src 'none'",
						].join("; "),
					},
				],
			},
		];
	},
};

export default nextConfig;
