/**
 * Tests for entitlement resolution (deny-overrides-grant).
 *
 * Negative cases first per `.claude/rules/testing.md`: a denied feature must
 * stay denied even when the plan grants it, and an unseeded tenant must fall
 * back to the plan-map default without crashing.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { type DbMock, makeDbMock } from "./__testutils__/db-mock";

// Hoisted holder so the vi.mock factory can reach the per-test db double.
const h = vi.hoisted(() => ({ current: null as DbMock | null }));

vi.mock("@/db", () => ({
	get db() {
		if (!h.current) throw new Error("db mock not initialised");
		return h.current.db;
	},
}));

import { tenants } from "@/db/schema";
import { getTableConfig } from "drizzle-orm/pg-core";
import {
	PLANS_V3,
	PLAN_ENTITLEMENTS,
	type Plan,
	mergeOverrides,
	resolveEntitlements,
} from "./entitlements";

function setDb(results: unknown[]): DbMock {
	const m = makeDbMock(results);
	h.current = m;
	return m;
}

describe("mergeOverrides (deny-overrides-grant primitive)", () => {
	it("REJECT: a present `false` override beats a `true` base (deny wins)", () => {
		const base = { ...PLAN_ENTITLEMENTS.business }; // byok_cmk: true
		expect(base.byok_cmk).toBe(true);
		const merged = mergeOverrides(base, { byok_cmk: false });
		expect(merged.byok_cmk).toBe(false);
	});

	it("inherits when override is null/undefined (no clobber)", () => {
		const base = { ...PLAN_ENTITLEMENTS.business };
		const merged = mergeOverrides(base, {
			byok_cmk: null,
			prompt_promotion_write: undefined,
		});
		expect(merged.byok_cmk).toBe(true);
		expect(merged.prompt_promotion_write).toBe(true);
	});

	it("coerces drizzle numeric strings to numbers for numeric fields", () => {
		const base = { ...PLAN_ENTITLEMENTS.team };
		const merged = mergeOverrides(base, {
			hot_gb_included: "120.5", // Drizzle numeric() columns come back as strings
			indexed_window_days: 120,
		});
		expect(merged.hot_gb_included).toBe(120.5);
		expect(typeof merged.hot_gb_included).toBe("number");
		expect(merged.indexed_window_days).toBe(120);
	});
});

describe("resolveEntitlements", () => {
	beforeEach(() => {
		h.current = null;
	});

	it("FALLBACK: unseeded tenant (no db id) returns the plan-map default", async () => {
		// No db id → resolver must not touch the DB at all.
		setDb([]);
		const ent = await resolveEntitlements(null, "team");
		expect(ent).toEqual(PLAN_ENTITLEMENTS.team);
	});

	it("FREE: the unbilled/canceled plan resolves the free-tier fallback", async () => {
		setDb([]);
		const ent = await resolveEntitlements(null, "free");
		expect(ent).toEqual(PLAN_ENTITLEMENTS.free);
		expect(ent.plan).toBe("free");
		expect(ent.ingest_gb_included).toBe(1);
		expect(ent.indexed_window_days).toBe(3);
		expect(ent.byok_cmk).toBe(false);
	});

	it("FRESH SIGNUP: tenants.plan defaults to 'free' → free entitlements", async () => {
		// A new tenant is inserted with no explicit plan, so the column default
		// governs what a fresh signup resolves to. Must be 'free', not 'builder'.
		const planCol = getTableConfig(tenants).columns.find(
			(c) => c.name === "plan",
		);
		expect(planCol?.default).toBe("free");

		setDb([]);
		const ent = await resolveEntitlements(null, "free");
		expect(ent.ingest_gb_included).toBe(1); // not Builder's 25 GB
		expect(ent.unlimited_seats).toBe(false); // not every-paid-tier's unlimited
	});

	it("FALLBACK: Postgres error mid-resolution falls back to plan-map default", async () => {
		// First DB read throws — resolver must swallow and return the map.
		setDb([new Error("connection refused")]);
		const ent = await resolveEntitlements("tenant-uuid", "builder");
		expect(ent.plan).toBe("builder");
		expect(ent.byok_cmk).toBe(false);
		expect(ent.unlimited_seats).toBe(true); // ADR-076: every paid tier
	});

	it("DENY-OVERRIDES-GRANT: workspace FALSE overrides a plan-granted TRUE", async () => {
		// plan_entitlements grants byok_cmk; workspace row denies it.
		setDb([
			[{ byok_cmk: true, fPr7Trajectory: true }], // planEntitlements row
			[{ fPr7Trajectory: false }], // workspaceEntitlements override → deny PR7
		]);
		const ent = await resolveEntitlements("tenant-uuid", "business");
		// business base already has byok_cmk true; the plan row doesn't carry it
		// through rowToOverrides (byok_cmk isn't a plan_entitlements column),
		// so it stays true from the base map. The PR7 flag is the deny target.
		expect(ent.f_pr7_trajectory).toBe(false);
	});

	it("GRANT: workspace TRUE flips an off-by-default predictive flag on", async () => {
		setDb([
			[{ fPr7Trajectory: false }], // plan default off
			[{ fPr7Trajectory: true }], // per-tenant grant on
		]);
		const ent = await resolveEntitlements("tenant-uuid", "enterprise");
		expect(ent.f_pr7_trajectory).toBe(true);
	});

	it("applies plan_entitlements six-meter overrides over the map default", async () => {
		setDb([
			[{ unlimitedSeats: true, indexedWindowDays: 120 }], // plan row
			[], // no workspace override (empty array → undefined first elem)
		]);
		const ent = await resolveEntitlements("tenant-uuid", "team");
		expect(ent.unlimited_seats).toBe(true);
		expect(ent.indexed_window_days).toBe(120);
	});
});

describe("tier landing matrix — every plan lands EXACTLY on plans.v3.json (ADR-076)", () => {
	// Compared against PLANS_V3 (the JSON) rather than hand-typed literals — this
	// is the guard that `buildPlanEntitlements`'s MAPPING is correct, not a pin
	// on numbers that could silently drift from the single source
	// (`.claude/rules/reference-tables.md`).
	const LOOKUP: Record<string, string> = {
		free: "free_v1",
		builder: "builder_v1",
		team: "team_v1",
		business: "business_v1",
		enterprise: "enterprise_v1",
	};

	for (const plan of Object.keys(LOOKUP)) {
		it(`${plan}: every ADR-076 field matches its plans.v3.json row exactly`, () => {
			const row = PLANS_V3.plans[LOOKUP[plan] as string];
			expect(row).toBeDefined();
			if (!row) return;
			const e = PLAN_ENTITLEMENTS[plan as Plan];
			expect(e.unlimited_seats).toBe(row.unlimited_seats);
			expect(e.f_sso).toBe(row.f_sso);
			expect(e.hot_gb_included).toBe(row.hot_gb_included);
			expect(e.ingest_gb_included).toBe(row.ingest_gb_included);
			expect(e.series_included).toBe(row.series_included);
			expect(e.scan_units_included).toBe(row.scan_units_included);
			expect(e.eval_runs_included).toBe(row.eval_runs_included);
			expect(e.indexed_window_days).toBe(row.indexed_window_days);
			expect(e.queryable_days).toBe(row.queryable_days);
			expect(e.ledger_days).toBe(row.ledger_days);
			expect(e.cold_archive_days).toBe(row.cold_archive_days);
			expect(e.overage_allowed).toBe(row.overage_allowed);
			expect(e.rate_limit_rpm).toBe(row.rate_limit_rpm);
		});
	}

	it("seats: Free is capped at 1; EVERY paid tier is unlimited (ADR-076, no ladder)", () => {
		expect(PLAN_ENTITLEMENTS.free.unlimited_seats).toBe(false);
		for (const plan of ["builder", "team", "business", "enterprise"] as const) {
			expect(PLAN_ENTITLEMENTS[plan].unlimited_seats).toBe(true);
		}
	});

	it("SSO: Team and above only (plans.v3.json f_sso)", () => {
		expect(PLAN_ENTITLEMENTS.free.f_sso).toBe(false);
		expect(PLAN_ENTITLEMENTS.builder.f_sso).toBe(false);
		expect(PLAN_ENTITLEMENTS.team.f_sso).toBe(true);
		expect(PLAN_ENTITLEMENTS.business.f_sso).toBe(true);
		expect(PLAN_ENTITLEMENTS.enterprise.f_sso).toBe(true);
	});

	it("Enterprise allowances are all `null` (custom), never a numeric quota", () => {
		const ent = PLAN_ENTITLEMENTS.enterprise;
		expect(ent.hot_gb_included).toBeNull();
		expect(ent.ingest_gb_included).toBeNull();
		expect(ent.series_included).toBeNull();
		expect(ent.scan_units_included).toBeNull();
		expect(ent.eval_runs_included).toBeNull();
	});
});

describe("audit_ledger — one source of truth = f_audit_addon", () => {
	beforeEach(() => {
		h.current = null;
	});

	it("GRANT: a workspace f_audit_addon=TRUE grant enables audit_ledger on any tier", async () => {
		setDb([
			[{ fAuditAddon: false }], // plan default: add-on off
			[{ fAuditAddon: true }], // per-tenant f_audit_addon export grant (migration 0005)
		]);
		const ent = await resolveEntitlements("tenant-uuid", "builder");
		expect(ent.audit_ledger).toBe(true);
	});

	it("REJECT: without the f_audit_addon grant audit_ledger stays FALSE — even on Business/Enterprise (add-on, never plan-bundled)", async () => {
		setDb([[{ fAuditAddon: false }], [{ fAuditAddon: false }]]);
		expect(
			(await resolveEntitlements("tenant-uuid", "business")).audit_ledger,
		).toBe(false);
		setDb([[{ fAuditAddon: false }], []]);
		expect(
			(await resolveEntitlements("tenant-uuid", "enterprise")).audit_ledger,
		).toBe(false);
	});

	it("REJECT: the plan-map fallback never grants audit (add-on-only at every tier)", async () => {
		setDb([]);
		for (const plan of [
			"free",
			"builder",
			"team",
			"business",
			"enterprise",
		] as const) {
			expect((await resolveEntitlements(null, plan)).audit_ledger).toBe(false);
		}
	});

	it("DENY-OVERRIDES-GRANT: workspace f_audit_addon=FALSE beats a plan TRUE", async () => {
		setDb([[{ fAuditAddon: true }], [{ fAuditAddon: false }]]);
		const ent = await resolveEntitlements("tenant-uuid", "business");
		expect(ent.audit_ledger).toBe(false);
	});
});

describe("prompt_promotion_write — ADR-009 Team+", () => {
	beforeEach(() => {
		h.current = null;
	});

	it("plan-map fallback: Team+ writes, Builder read-only, Free none", () => {
		expect(PLAN_ENTITLEMENTS.free.prompt_promotion_write).toBe(false);
		expect(PLAN_ENTITLEMENTS.builder.prompt_promotion_write).toBe(false);
		expect(PLAN_ENTITLEMENTS.builder.prompt_promotion_read).toBe(true);
		expect(PLAN_ENTITLEMENTS.team.prompt_promotion_write).toBe(true);
		expect(PLAN_ENTITLEMENTS.business.prompt_promotion_write).toBe(true);
		expect(PLAN_ENTITLEMENTS.enterprise.prompt_promotion_write).toBe(true);
	});

	it("GRANT: plan row f_prompt_promotion_write=TRUE resolves through (Migration 0004/0005 seed)", async () => {
		setDb([[{ fPromptPromotionWrite: true }], []]);
		const ent = await resolveEntitlements("tenant-uuid", "team");
		expect(ent.prompt_promotion_write).toBe(true);
	});

	it("REJECT: workspace f_prompt_promotion_write=FALSE beats the Team plan TRUE (deny wins)", async () => {
		setDb([
			[{ fPromptPromotionWrite: true }],
			[{ fPromptPromotionWrite: false }],
		]);
		const ent = await resolveEntitlements("tenant-uuid", "team");
		expect(ent.prompt_promotion_write).toBe(false);
	});
});

describe("full-capture gate (f_full_capture)", () => {
	beforeEach(() => {
		h.current = null;
	});

	it("REJECT: workspace f_full_capture=false beats a Business plan grant (deny wins, audit off)", () => {
		const base = { ...PLAN_ENTITLEMENTS.business };
		expect(base.f_full_capture).toBe(true);
		expect(mergeOverrides(base, { f_full_capture: false }).f_full_capture).toBe(
			false,
		);
	});

	it("PLAN GRANT: full capture = Business + Enterprise base; OFF for Free/Builder/Team", async () => {
		setDb([]); // null tenant → no db read
		expect((await resolveEntitlements(null, "business")).f_full_capture).toBe(
			true,
		);
		expect((await resolveEntitlements(null, "enterprise")).f_full_capture).toBe(
			true,
		);
		expect((await resolveEntitlements(null, "free")).f_full_capture).toBe(
			false,
		);
		expect((await resolveEntitlements(null, "builder")).f_full_capture).toBe(
			false,
		);
		expect((await resolveEntitlements(null, "team")).f_full_capture).toBe(
			false,
		);
	});

	it("AUDIT FORCE: an active f_audit_addon grant forces full capture on a tail tier", async () => {
		// Audit now arrives via the workspace f_audit_addon grant,
		// not the legacy tenants.auditEnabled column.
		setDb([[{ fAuditAddon: false }], [{ fAuditAddon: true }]]);
		const ent = await resolveEntitlements("tenant-uuid", "builder");
		expect(ent.audit_ledger).toBe(true);
		expect(ent.f_full_capture).toBe(true);
	});

	it("AUDIT FORCE is NON-OVERRIDABLE: workspace f_full_capture=false + audit grant → still full", async () => {
		// plan grants full, workspace tries to deny it, but the export grant
		// (f_audit_addon) is active → the deny is overridden back to TRUE (non-overridable guarantee).
		setDb([
			[{ fFullCapture: true, fAuditAddon: false }],
			[{ fFullCapture: false, fAuditAddon: true }],
		]);
		const ent = await resolveEntitlements("tenant-uuid", "business");
		expect(ent.f_full_capture).toBe(true);
	});

	it("DENY-OVERRIDES-GRANT applies when audit is OFF: workspace false → false", async () => {
		setDb([
			[{ fFullCapture: true, fAuditAddon: false }],
			[{ fFullCapture: false }],
		]);
		const ent = await resolveEntitlements("tenant-uuid", "business");
		expect(ent.f_full_capture).toBe(false);
	});
});
