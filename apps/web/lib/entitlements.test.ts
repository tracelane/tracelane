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
	PLAN_ENTITLEMENTS,
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
			eval_gates: undefined,
		});
		expect(merged.byok_cmk).toBe(true);
		expect(merged.eval_gates).toBe(true);
	});

	it("coerces drizzle numeric strings to numbers for numeric fields", () => {
		const base = { ...PLAN_ENTITLEMENTS.team };
		const merged = mergeOverrides(base, {
			overage_hard_cap_multiplier: "5.0",
			retention_days: 120,
		});
		expect(merged.overage_hard_cap_multiplier).toBe(5.0);
		expect(typeof merged.overage_hard_cap_multiplier).toBe("number");
		expect(merged.retention_days).toBe(120);
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
		expect(ent.trace_quota_monthly).toBe(10_000);
		expect(ent.retention_days).toBe(7);
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
		expect(ent.trace_quota_monthly).toBe(10_000); // not Builder's 150K
	});

	it("FALLBACK: Postgres error mid-resolution falls back to plan-map default", async () => {
		// First DB read throws — resolver must swallow and return the map.
		setDb([new Error("connection refused")]);
		const ent = await resolveEntitlements("tenant-uuid", "builder");
		expect(ent.plan).toBe("builder");
		expect(ent.byok_cmk).toBe(false);
		expect(ent.seat_cap_max).toBe(1);
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

	it("applies plan_entitlements numeric seat caps over the map default", async () => {
		setDb([
			[{ seatCapMax: 25, retentionDays: 90 }], // plan row
			[], // no workspace override (empty array → undefined first elem)
		]);
		const ent = await resolveEntitlements("tenant-uuid", "team");
		expect(ent.seat_cap_max).toBe(25);
		expect(ent.retention_days).toBe(90);
	});
});

describe("tier landing matrix — what each plan lands with (billing.md / ADR-020)", () => {
	// The authoritative per-tier numbers. Drift between this map and
	// PLAN_ENTITLEMENTS is a bug (billing.md "Seat caps — one source of truth"
	// + "Drift ... is a bug; ADR-020 lists the authoritative numbers"). This is
	// the guard that a new signup on any tier "lands properly" — right seat cap,
	// retention, and quota.
	const MATRIX = {
		free: { included: 1, max: 1, retention: 7, quota: 10_000 },
		builder: { included: 1, max: 1, retention: 30, quota: 150_000 },
		team: { included: 10, max: 25, retention: 90, quota: 1_000_000 },
		business: { included: 25, max: 50, retention: 180, quota: 5_000_000 },
		enterprise: { included: 0, max: 0, retention: 365, quota: 25_000_000 },
	} as const;

	for (const [plan, exp] of Object.entries(MATRIX)) {
		it(`${plan}: seat_cap_included=${exp.included}, seat_cap_max=${exp.max} (0=unlimited), retention=${exp.retention}d, quota=${exp.quota}`, () => {
			const e = PLAN_ENTITLEMENTS[plan as keyof typeof MATRIX];
			expect(e.seat_cap_included).toBe(exp.included);
			expect(e.seat_cap_max).toBe(exp.max);
			expect(e.retention_days).toBe(exp.retention);
			expect(e.trace_quota_monthly).toBe(exp.quota);
		});
	}

	it("seat cap ordering is monotonic non-decreasing across paid tiers; enterprise is the 0=unlimited sentinel", () => {
		expect(PLAN_ENTITLEMENTS.builder.seat_cap_max).toBeLessThanOrEqual(
			PLAN_ENTITLEMENTS.team.seat_cap_max,
		);
		expect(PLAN_ENTITLEMENTS.team.seat_cap_max).toBeLessThanOrEqual(
			PLAN_ENTITLEMENTS.business.seat_cap_max,
		);
		// Enterprise uses 0 as the unlimited sentinel (NOT a smaller cap than Business).
		expect(PLAN_ENTITLEMENTS.enterprise.seat_cap_max).toBe(0);
	});
});

describe("audit_ledger — one source of truth = f_audit_addon", () => {
	beforeEach(() => {
		h.current = null;
	});

	it("GRANT: a workspace f_audit_addon=TRUE grant enables audit_ledger on any tier", async () => {
		setDb([
			[{ fAuditAddon: false }], // plan default: add-on off
			[{ fAuditAddon: true }], // per-tenant Audit SKU grant (migration 0005)
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
		// not the legacy tenants.auditEnabled column.
		setDb([[{ fAuditAddon: false }], [{ fAuditAddon: true }]]);
		const ent = await resolveEntitlements("tenant-uuid", "builder");
		expect(ent.audit_ledger).toBe(true);
		expect(ent.f_full_capture).toBe(true);
	});

	it("AUDIT FORCE is NON-OVERRIDABLE: workspace f_full_capture=false + audit grant → still full", async () => {
		// plan grants full, workspace tries to deny it, but the Audit SKU is
		// active → the deny is overridden back to TRUE (non-overridable guarantee).
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
