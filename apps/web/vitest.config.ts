/**
 * Vitest config for the Tracelane dashboard.
 *
 * API-route handler unit tests run in the `node` environment (no DOM needed).
 * The `@/*` path alias mirrors tsconfig.json so handler imports resolve the
 * same way they do under Next.js. All external clients (Drizzle/Neon,
 * WorkOS, ClickHouse, the gateway) are mocked per-test — no real network,
 * per `.claude/rules/testing.md`.
 */

import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	// Automatic JSX runtime (react/jsx-runtime) — matches Next.js prod, so local
	// `.tsx` components (which don't `import React`) can be rendered in tests
	// (e.g. the audit-ledger verdict render proof). Without this, esbuild emits
	// classic `React.createElement` and rendering a local component throws
	// "React is not defined".
	esbuild: { jsx: "automatic" },
	resolve: {
		alias: {
			"@": fileURLToPath(new URL("./", import.meta.url)),
			// next/navigation calls useRouter() which requires a router context —
			// not available in `renderToStaticMarkup` node-env tests. Stub it so
			// the audit-ledger-verify.test.ts can SSR-render AuditLedgerView.
			"next/navigation": fileURLToPath(
				new URL("./__mocks__/next-navigation-stub.ts", import.meta.url),
			),
		},
	},
	test: {
		environment: "node",
		include: ["**/*.test.ts"],
		exclude: ["node_modules", ".next"],
		clearMocks: true,
		restoreMocks: true,
	},
});
