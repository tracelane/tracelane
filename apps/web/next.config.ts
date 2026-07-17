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
					{
						key: "Content-Security-Policy",
						value: [
							"default-src 'self'",
							"script-src 'self' 'unsafe-eval' 'unsafe-inline'", // 'unsafe-eval' for WebGL shader compilation
							"style-src 'self' 'unsafe-inline'",
							"img-src 'self' data: blob:",
							"connect-src 'self' wss:",
						].join("; "),
					},
				],
			},
		];
	},
};

export default nextConfig;
