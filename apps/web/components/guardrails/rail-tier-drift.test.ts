/**
 * GWY-33 drift guard — the in-app rail→tier map must equal what the BINARY does.
 *
 * 2026-08-04) made R3_pinning and R4_trifecta UNGATED in the gateway
 * (`Rail::feature()` → `None`), but `lib/guardrail-rails.ts` kept them
 * `gated: true` with `RAIL_TIER[...] = "Team"`. Result: every Free and Builder
 * tenant opening /guardrails saw a "Team 🔒" upsell badge on two rails they were
 * already running. Nothing errored, no request changed, no one was billed
 * wrongly — so nothing looked wrong. Exactly the shape `.claude/rules/tenancy.md`
 * warns about, inverted into the customer's face instead of the gate.
 *
 * So this asserts the MECHANISM, not the outcome. Three independent sources are
 * parsed off disk and joined; the TS map must agree with all three:
 *
 *   crates/gateway/src/guardrail/rails/*.rs   `Rail::name()` + `Rail::feature()`
 *       → the ONLY authority on free-vs-gated. `None` means the rail never
 *         consults the entitlement gate, so no tier can gate it.
 *   crates/gateway/src/guardrail/rail.rs      `RailGate::from_resolved`
 *       → GuardrailFeature variant ↔ `f_guardrail_*` Postgres column.
 *   apps/web/db/seed.mjs                      `PLANS`
 *       → the lowest plan whose grant for that column is true = the tier label,
 *         i.e. a real purchase path rather than a word.
 *
 * A parse that finds the wrong shape FAILS rather than silently checking
 * nothing — a guard that can quietly match zero rails is not a guard.
 *
 * The negative tests below are this guard's `--selftest`: they replay the
 */

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { RAIL_ROSTER, RAIL_TIER, type RailMeta } from "@/lib/guardrail-rails";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { RailRoster } from "../../app/guardrails/RailRoster";

const repoFile = (rel: string): string =>
	fileURLToPath(new URL(`../../../../${rel}`, import.meta.url));

/** Rust/JS comments carry rail names in prose; strip them before matching. */
function stripComments(src: string): string {
	return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/** Ledger rail id → the `GuardrailFeature` variant gating it, or null if free. */
function rustRailGating(): Map<string, string | null> {
	const dir = repoFile("crates/gateway/src/guardrail/rails");
	const out = new Map<string, string | null>();
	for (const f of readdirSync(dir)) {
		if (!f.endsWith(".rs") || f === "mod.rs") continue;
		const src = stripComments(readFileSync(`${dir}/${f}`, "utf8"));
		// One file can hold several rails (r3_tool_safety.rs = R3_schema + R3_pinning).
		for (const chunk of src.split(/impl\s+Rail\s+for\s+/).slice(1)) {
			const id = chunk.match(/fn\s+name\s*\([^)]*\)[^{]*\{\s*"([^"]+)"/)?.[1];
			const body = chunk.match(
				/fn\s+feature\s*\([^)]*\)\s*->\s*Option<GuardrailFeature>\s*\{([\s\S]*?)\n\s{4}\}/,
			)?.[1];
			if (!id || body === undefined) continue;
			const variant = body.match(/Some\(GuardrailFeature::(\w+)\)/)?.[1];
			out.set(id, variant ?? null);
		}
	}
	return out;
}

/** `GuardrailFeature` variant → its `f_guardrail_*` column, read from Rust. */
function featureColumns(): Map<string, string> {
	const src = stripComments(
		readFileSync(repoFile("crates/gateway/src/guardrail/rail.rs"), "utf8"),
	);
	const body = src.match(/fn\s+from_resolved\s*\([\s\S]*?\n\s{4}\}/)?.[0] ?? "";
	const out = new Map<string, string>();
	for (const m of body.matchAll(
		/resolved\.(f_guardrail_\w+)[\s\S]{0,120}?GuardrailFeature::(\w+)/g,
	)) {
		const [, column, variant] = m;
		if (column && variant) out.set(variant, column);
	}
	return out;
}

/** Human plan label per `plan_lookup_key`, in ladder order. */
const PLAN_LABEL: Record<string, string> = {
	free_v1: "Free",
	builder_v1: "Builder",
	team_v1: "Team",
	business_v1: "Business",
	enterprise_v1: "Enterprise",
};

/**
 * `f_guardrail_*` column → the label of the LOWEST plan granting it, or null
 * when the free plan already grants it (then it is not a purchase path at all).
 */
function seedUnlockTier(): Map<string, string | null> {
	const src = readFileSync(repoFile("apps/web/db/seed.mjs"), "utf8");
	const block = stripComments(
		src.match(/const PLANS = \[([\s\S]*?)\n\];/)?.[1] ?? "",
	);
	// Each plan is one `[ "key", …, gr2, gr3_pinning, gr4, gr5, gr6, gr7 ]` row;
	// the six guardrail grants are always the final six columns.
	const plans = [...block.matchAll(/\[([\s\S]*?)\]/g)].map((m) =>
		(m[1] ?? "")
			.split(",")
			.map((t) => t.trim())
			.filter(Boolean),
	);
	const COLS = [
		"f_guardrail_r2",
		"f_guardrail_r3_pinning",
		"f_guardrail_r4",
		"f_guardrail_r5",
		"f_guardrail_r6",
		"f_guardrail_r7",
	];
	const out = new Map<string, string | null>();
	for (const [i, col] of COLS.entries()) {
		let tier: string | null = null;
		for (const p of plans) {
			const key = p[0]?.replace(/"/g, "") ?? "";
			if (p.slice(-6)[i] !== "true") continue;
			tier = key === "free_v1" ? null : (PLAN_LABEL[key] ?? key);
			break;
		}
		out.set(col, tier);
	}
	return out;
}

/** The joined ground truth: rail id → the tier that unlocks it, or null = free. */
function codeTruth(): Map<string, string | null> {
	const gating = rustRailGating();
	const cols = featureColumns();
	const tiers = seedUnlockTier();
	const truth = new Map<string, string | null>();
	for (const [railId, variant] of gating) {
		if (variant === null) {
			truth.set(railId, null);
			continue;
		}
		const col = cols.get(variant);
		if (!col) throw new Error(`no f_guardrail_* column for ${variant}`);
		truth.set(railId, tiers.get(col) ?? null);
	}
	return truth;
}

/**
 * Every way the shipped copy can lie about entitlement, as a list of messages.
 * Empty = the UI tells the truth. This is the checker the negative tests attack.
 */
function drift(
	roster: readonly RailMeta[],
	tierMap: Record<string, string>,
	truth: Map<string, string | null>,
): string[] {
	const bad: string[] = [];
	for (const m of roster) {
		const unlockedBy = truth.get(m.id);
		if (unlockedBy === undefined) {
			bad.push(`${m.id}: in the UI roster but no such rail in the gateway`);
			continue;
		}
		const reallyGated = unlockedBy !== null;
		if (m.gated !== reallyGated) {
			bad.push(
				`${m.id}: UI says gated=${m.gated}, Rail::feature() says gated=${reallyGated}`,
			);
		}
		const shown = tierMap[m.id];
		if (!reallyGated && shown) {
			bad.push(
				`${m.id}: UI upsells "${shown}" for a rail every plan already runs`,
			);
		}
		if (reallyGated && shown !== unlockedBy) {
			bad.push(
				`${m.id}: UI says "${shown ?? "(none)"}", seed unlocks at "${unlockedBy}"`,
			);
		}
	}
	for (const id of Object.keys(tierMap)) {
		if (!roster.some((m) => m.id === id)) {
			bad.push(`${id}: tier entry for a rail that is not in the roster`);
		}
	}
	return bad;
}

// ── the parse itself must be load-bearing ────────────────────────────────────

describe("parse integrity (a guard that matches nothing is not a guard)", () => {
	it("finds all 9 rails in the gateway, with 4 gated and 5 free", () => {
		const g = rustRailGating();
		expect([...g.keys()].sort()).toEqual(
			[
				"R1_cost",
				"R2_secrets_pii",
				"R3_pinning",
				"R3_schema",
				"R4_trifecta",
				"R5_format",
				"R6_sysprompt_leak",
				"R7_topic_competitor",
				"R8_injection",
			].sort(),
		);
		expect([...g.values()].filter((v) => v !== null)).toHaveLength(4);
	});

	it("maps all six GuardrailFeature variants to f_guardrail_* columns", () => {
		expect(featureColumns().size).toBe(6);
	});

	it("derives Team as the unlock tier for the four paid rails", () => {
		const t = seedUnlockTier();
		expect(t.get("f_guardrail_r2")).toBe("Team");
		expect(t.get("f_guardrail_r5")).toBe("Team");
		expect(t.get("f_guardrail_r6")).toBe("Team");
		expect(t.get("f_guardrail_r7")).toBe("Team");
		// Granted on free_v1 → not a purchase path, whatever the column says.
		expect(t.get("f_guardrail_r3_pinning")).toBeNull();
		expect(t.get("f_guardrail_r4")).toBeNull();
	});
});

// ── the claim GWY-33 makes ───────────────────────────────────────────────────

describe("the shipped rail→tier map equals the gateway + the seed", () => {
	it("has zero drift", () => {
		expect(drift(RAIL_ROSTER, RAIL_TIER, codeTruth())).toEqual([]);
	});

	it("never upsells a rail the free tier already runs (B-188)", () => {
		for (const id of [
			"R1_cost",
			"R3_schema",
			"R3_pinning",
			"R4_trifecta",
			"R8_injection",
		]) {
			expect(RAIL_TIER[id], `${id} must not carry a tier`).toBeUndefined();
			expect(RAIL_ROSTER.find((m) => m.id === id)?.gated).toBe(false);
		}
	});

	it("still names Team for the four rails that ARE gated", () => {
		expect(RAIL_TIER).toEqual({
			R2_secrets_pii: "Team",
			R5_format: "Team",
			R6_sysprompt_leak: "Team",
			R7_topic_competitor: "Team",
		});
	});
});

// ── --selftest: prove the checker BLOCKS, not just that it passes ────────────

describe("selftest — the guard rejects each way the map can lie", () => {
	const truth = codeTruth();
	const withGated = (id: string, gated: boolean): RailMeta[] =>
		RAIL_ROSTER.map((m) => (m.id === id ? { ...m, gated } : m));

	it("catches the exact pre-B-188 regression (R3_pinning + R4 sold as Team)", () => {
		const stale = RAIL_ROSTER.map((m) =>
			m.id === "R3_pinning" || m.id === "R4_trifecta"
				? { ...m, gated: true }
				: m,
		);
		const bad = drift(
			stale,
			{ ...RAIL_TIER, R3_pinning: "Team", R4_trifecta: "Team" },
			truth,
		);
		expect(bad.join("\n")).toMatch(/R3_pinning: UI says gated=true/);
		expect(bad.join("\n")).toMatch(/R4_trifecta: UI says gated=true/);
		expect(bad.join("\n")).toMatch(/R3_pinning: UI upsells "Team"/);
		expect(bad.join("\n")).toMatch(/R4_trifecta: UI upsells "Team"/);
	});

	it("catches a genuinely gated rail shown as free", () => {
		const bad = drift(withGated("R2_secrets_pii", false), RAIL_TIER, truth);
		expect(bad.join("\n")).toMatch(
			/R2_secrets_pii: UI says gated=false, Rail::feature\(\) says gated=true/,
		);
	});

	it("catches a wrong tier label (the old Business copy)", () => {
		const bad = drift(
			RAIL_ROSTER,
			{ ...RAIL_TIER, R2_secrets_pii: "Business" },
			truth,
		);
		expect(bad.join("\n")).toMatch(
			/R2_secrets_pii: UI says "Business", seed unlocks at "Team"/,
		);
	});

	it("catches a tier entry for a rail the gateway does not have", () => {
		const bad = drift(RAIL_ROSTER, { ...RAIL_TIER, R9_ghost: "Team" }, truth);
		expect(bad.join("\n")).toMatch(/R9_ghost: tier entry for a rail/);
	});
});

// ── what a Free tenant actually SEES ─────────────────────────────────────────

describe("rendered /guardrails roster — a Free tenant sees no false lock", () => {
	// No live verdicts = the state a fresh/Free workspace is in, which is exactly
	// when `locked = gated && !live` decides whether to show the upsell badge.
	const html = renderToStaticMarkup(
		createElement(RailRoster, { live: [], range: "24h" }),
	);
	/** The markup for one rail row, from its id label back to the row start. */
	const rowOf = (id: string): string => {
		const at = html.indexOf(`>${id}<`);
		expect(at, `${id} row must render`).toBeGreaterThan(-1);
		return html.slice(html.lastIndexOf("<tr", at), at);
	};

	it("renders every rail, free and gated alike", () => {
		for (const m of RAIL_ROSTER) expect(html).toContain(`>${m.id}<`);
	});

	it("shows NO tier badge on the rails B-188 made free", () => {
		for (const id of [
			"R1_cost",
			"R3_schema",
			"R3_pinning",
			"R4_trifecta",
			"R8_injection",
		]) {
			const row = rowOf(id);
			expect(row, `${id} must not be sold`).not.toMatch(
				/Team|Business|Advanced/,
			);
		}
	});

	it("still shows the Team badge on the four gated rails", () => {
		for (const id of [
			"R2_secrets_pii",
			"R5_format",
			"R6_sysprompt_leak",
			"R7_topic_competitor",
		]) {
			expect(rowOf(id), `${id} must show its purchase path`).toContain("Team");
		}
	});
});
