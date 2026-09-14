/**
 * The ADR-076 / BILL-01 ruled pricing model, for the marketing site.
 *
 * Reads `apps/web/db/plans.v3.json` DIRECTLY — that file is the single
 * source `scripts/ci/check-pricing-copy-vs-seed.py` checks every public
 * surface against (`.claude/rules/reference-tables.md`). No price,
 * allowance, window or seat figure is ever typed here.
 *
 * `node:fs` rather than a JSON import: this site builds fully static
 * (no `output`/`adapter` in `astro.config.mjs`, so every `.astro` frontmatter
 * runs once at `astro build` time in Node — never in the deployed Worker,
 * which serves the resulting static HTML) — `readFileSync` avoids depending
 * on a bundler's JSON-import-assertion behaviour, which differs between
 * Vite (this site's build) and the plain `node --test` runner `site.test.ts`
 * uses, so ONE loader works identically in both.
 *
 * The path is resolved from `process.cwd()` by walking up to the monorepo
 * root (`pnpm-workspace.yaml`), NOT from `new URL(relative, import.meta.url)`
 * — that broke under Astro's prerender build: Vite relocates this module into
 * `dist/.prerender/chunks/…`, so `import.meta.url` at runtime pointed at the
 * BUNDLED chunk's path, not this source file's, and a fixed `"../../../"`
 * climbed the wrong number of directories from there (found live, 2026-09-13:
 * it resolved to `apps/site/web/db/plans.v3.json` — three levels up from the
 * chunk, not from here). `process.cwd()` is a runtime value the bundler
 * cannot relocate, and every invocation in this repo (`astro build`/`dev`/
 * `check`, and `node --test`) runs with cwd = `apps/site`.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

function findMonorepoRoot(startDir: string): string {
	let dir = startDir;
	for (let i = 0; i < 10; i++) {
		if (existsSync(join(dir, "pnpm-workspace.yaml"))) return dir;
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	throw new Error(`could not find the monorepo root above ${startDir}`);
}

const PLANS_PATH = join(
	findMonorepoRoot(process.cwd()),
	"apps/web/db/plans.v3.json",
);

export interface PlanRow {
	name: string;
	price_monthly_usd: number | null;
	price_annual_month_usd: number | null;
	price_from_usd: number | null;
	hot_gb_included: number | null;
	ingest_gb_included: number | null;
	series_included: number | null;
	scan_units_included: number | null;
	eval_runs_included: number | null;
	indexed_window_days: number;
	queryable_days: number;
	ledger_days: number;
	cold_archive_days: number | null;
	unlimited_seats: boolean;
	f_sso: boolean;
	overage_allowed: boolean;
	rate_limit_rpm: number | null;
}

export interface PlansV3 {
	meters: {
		ingest_usd_per_gb: number;
		hot_window_usd_per_gb_month_ladder: [number, number | null, number][];
		series_usd_per_series_month: number;
		query_usd_per_scan_unit: number;
		cold_usd_per_gb_month: number;
		eval_usd_per_judge_run: number;
		never_metered: string[];
	};
	policy: {
		price_protection_months: number;
		free_idle_reclaim_days: number;
		dunning_retry_days: number[];
		dunning_data_hold_days: number;
		refund_days_base_first_cycle: number;
	};
	plans: Record<string, PlanRow>;
}

export const PLANS_V3: PlansV3 = JSON.parse(readFileSync(PLANS_PATH, "utf-8"));

export const LADDER = [
	"free_v1",
	"builder_v1",
	"team_v1",
	"business_v1",
	"enterprise_v1",
] as const;

export function plan(key: (typeof LADDER)[number]): PlanRow {
	const row = PLANS_V3.plans[key];
	if (!row) throw new Error(`plans.v3.json has no row for ${key}`);
	return row;
}

/** `1234` -> "1.2K"; `null` -> "custom". */
export function formatCount(n: number | null): string {
	if (n === null) return "custom";
	if (n >= 1_000_000) {
		const m = n / 1_000_000;
		return `${Number.isInteger(m) ? m : m.toFixed(1)}M`;
	}
	if (n >= 1_000) {
		const k = n / 1_000;
		return `${Number.isInteger(k) ? k : k.toFixed(1)}K`;
	}
	return n.toLocaleString("en-US");
}

/** `0.25` -> "0.25 GB"; `1500` -> "1.5 TB"; `null` -> "custom". */
export function formatGb(gb: number | null): string {
	if (gb === null) return "custom";
	if (gb >= 1000) {
		const tb = gb / 1000;
		return `${Number.isInteger(tb) ? tb : tb.toFixed(1)} TB`;
	}
	return `${Number.isInteger(gb) ? gb : gb.toFixed(2)} GB`;
}

/** `3` -> "3 days"; `730` -> "2 years". */
export function formatDays(days: number, plusOpenEnded = false): string {
	if (days % 365 === 0 && days >= 365) {
		const years = days / 365;
		return `${years} year${years === 1 ? "" : "s"}${plusOpenEnded ? "+" : ""}`;
	}
	return `${days} day${days === 1 ? "" : "s"}${plusOpenEnded ? "+" : ""}`;
}

/** `$0`; `$29/mo`; `from $2,499/mo`. */
export function formatPrice(
	row: PlanRow,
	interval: "month" | "year" = "month",
): { amount: string; suffix: string; fromLabel: boolean } {
	if (row.price_from_usd !== null) {
		return {
			amount: `$${row.price_from_usd.toLocaleString("en-US")}`,
			suffix: "/mo",
			fromLabel: true,
		};
	}
	if (row.price_monthly_usd === 0)
		return { amount: "$0", suffix: "", fromLabel: false };
	const usd =
		interval === "year" && row.price_annual_month_usd !== null
			? row.price_annual_month_usd
			: row.price_monthly_usd;
	return {
		amount: `$${(usd ?? 0).toLocaleString("en-US")}`,
		suffix: "/mo",
		fromLabel: false,
	};
}
