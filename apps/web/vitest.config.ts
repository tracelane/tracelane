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
		// `.tsx` INCLUDED DELIBERATELY. This was `["**/*.test.ts"]`, so a test written
		// as `.test.tsx` was silently never collected — it did not fail, it did not
		// appear in the count, it simply did not exist as far as CI was concerned. That
		// is the CLASS-1 shape (`docs/reference/TRAPS.md` §1): a control that is present,
		// looks configured, and blocks nothing. Found 2026-08-15 when a render test moved
		// to `.tsx` to use JSX and the suite total did not change.
		include: ["**/*.test.ts", "**/*.test.tsx"],
		exclude: ["node_modules", ".next"],
		clearMocks: true,
		restoreMocks: true,
		// 2026-08-10: vitest's defaults (10s hook / 5s test) are far too tight for the
		// PGlite e2e suites, which boot an in-process WASM Postgres and apply the
		// schema — ~28s measured on an IDLE box. Whichever suite runs first pays the
		// cold-start cost, so the failure moved around and read as flakiness.
		//
		// It failed `verify-all.sh` on a DOCS-ONLY change, which is the worst kind of
		// red: a gate that goes off on unrelated work is one people learn to ignore,
		// and this repo already has a name for controls that stop being load-bearing.
		//
		// These budgets exist to catch a HANG, not to police duration — so they are
		// deliberately generous. If one fires, something is genuinely stuck.
		//
		// THIS IS A SYMPTOM FIX, AND IT SHOULD NOT BE READ AS THE ANSWER. Booting a
		// WASM Postgres per suite costs ~28s and will only grow as the schema does,
		// and 180s means a genuinely hung suite now takes three minutes to fail
		// instead of thirty seconds. That trade is right TODAY — a gate that reddens
		// on docs-only changes gets ignored, and an ignored control is the failure
		// mode this repo keeps re-learning — but the real fix is to stop paying the
		// boot cost per suite: one shared PGlite instance across the e2e suites, or a
		// the raised number does not become the resting state.
		hookTimeout: 180_000,
		testTimeout: 60_000,
	},
});
