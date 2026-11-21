/**
 * ACT-20 — the pure decision behind the owner switch for action control. Every state is
 * decided here so no browser or database is needed to prove it. Negative cases first.
 */
import { describe, expect, it } from "vitest";
import {
	ACTION_CONTROL_OFF_WARNING,
	ACTION_CONTROL_ON_CONFIRMATION,
	ACTION_CONTROL_SUMMARY,
	type ChangeInput,
	PROPAGATION_NOTE,
	decideActionControlChange,
} from "./action-control-setting";

const base: ChangeInput = {
	role: "admin",
	current: false,
	requested: true,
	confirmed: true,
};

describe("decideActionControlChange — negative cases", () => {
	it("refuses a caller who is not an owner or admin", () => {
		const d = decideActionControlChange({ ...base, role: "other" });
		expect(d).toMatchObject({ action: "refuse", reason: "not_owner" });
	});
	it("refuses a caller whose role could not be verified", () => {
		const d = decideActionControlChange({ ...base, role: "unverified" });
		expect(d).toMatchObject({ action: "refuse", reason: "role_unverified" });
	});
	it("refuses an unconfirmed switch on", () => {
		const d = decideActionControlChange({ ...base, confirmed: false });
		expect(d).toMatchObject({
			action: "refuse",
			reason: "confirmation_required",
		});
	});
	it("refuses an unconfirmed switch off and carries the warning", () => {
		const d = decideActionControlChange({
			...base,
			current: true,
			requested: false,
			confirmed: false,
		});
		expect(d).toMatchObject({
			action: "refuse",
			reason: "confirmation_required",
			warning: ACTION_CONTROL_OFF_WARNING,
		});
	});
	it("a non-owner is refused before confirmation is looked at", () => {
		const d = decideActionControlChange({
			...base,
			role: "other",
			confirmed: false,
		});
		expect(d).toMatchObject({ reason: "not_owner" });
	});
	it("an unverified role is refused even for an unchanged value", () => {
		const d = decideActionControlChange({
			...base,
			role: "unverified",
			requested: false,
		});
		expect(d.action).toBe("refuse");
	});
	it("a non-owner asking for the current value is still refused, not a no-op", () => {
		const d = decideActionControlChange({
			...base,
			role: "other",
			current: true,
			requested: true,
		});
		expect(d.action).toBe("refuse");
	});
});

describe("decideActionControlChange — positive cases", () => {
	it("an admin confirming ON writes true with no warning", () => {
		expect(decideActionControlChange(base)).toEqual({
			action: "write",
			next: true,
			warning: null,
		});
	});
	it("an admin confirming OFF writes false and carries the warning", () => {
		const d = decideActionControlChange({
			...base,
			current: true,
			requested: false,
		});
		expect(d).toEqual({
			action: "write",
			next: false,
			warning: ACTION_CONTROL_OFF_WARNING,
		});
	});
	it("asking for the current value is a no-op even when unconfirmed", () => {
		expect(
			decideActionControlChange({
				...base,
				current: true,
				requested: true,
				confirmed: false,
			}),
		).toEqual({ action: "noop", warning: null });
	});
	it("OFF to OFF is a no-op", () => {
		expect(
			decideActionControlChange({ ...base, requested: false }).action,
		).toBe("noop");
	});
});

describe("copy", () => {
	it("the warning names both consequences", () => {
		expect(ACTION_CONTROL_OFF_WARNING).toMatch(/standard per-tool rules/);
		expect(ACTION_CONTROL_OFF_WARNING).toMatch(/approvals/);
	});
	it("the summary and ON confirmation do not claim approval or a receipt for every call", () => {
		for (const s of [ACTION_CONTROL_SUMMARY, ACTION_CONTROL_ON_CONFIRMATION])
			expect(s).not.toMatch(/receipt|need an approved|will require approval/i);
		expect(ACTION_CONTROL_SUMMARY).toMatch(/allow them, deny them or hold/);
		expect(ACTION_CONTROL_SUMMARY).toMatch(/signed action ledger/);
	});
	it("the propagation note says usually, not a guarantee", () => {
		expect(PROPAGATION_NOTE).not.toMatch(/at most/);
		expect(PROPAGATION_NOTE).toMatch(/^Usually takes effect within 15 minutes/);
	});
	it("the propagation note states the bound and the quiet-period caveat", () => {
		expect(PROPAGATION_NOTE).toMatch(/15 minutes/);
		expect(PROPAGATION_NOTE).toMatch(/quiet period/);
	});
	it("visible copy carries no internal identifiers", () => {
		for (const s of [
			ACTION_CONTROL_OFF_WARNING,
			PROPAGATION_NOTE,
			ACTION_CONTROL_SUMMARY,
			ACTION_CONTROL_ON_CONFIRMATION,
		]) {
			expect(s).not.toMatch(/\b(ACT|SRE|ADR|B)-\d+|tenant|org_id|workos/i);
		}
	});
});

describe("invariant sweep over every input combination", () => {
	const roles = ["admin", "other", "unverified"] as const;
	const bools = [false, true] as const;
	const combos: ChangeInput[] = [];
	for (const role of roles)
		for (const current of bools)
			for (const requested of bools)
				for (const confirmed of bools)
					combos.push({ role, current, requested, confirmed });

	it("covers 24 combinations", () => {
		expect(combos).toHaveLength(24);
	});

	it.each(combos)("invariants hold for %j", (input) => {
		const d = decideActionControlChange(input);
		// A non-owner or unverified caller never writes.
		if (input.role !== "admin") expect(d.action).toBe("refuse");
		// Unconfirmed never writes.
		if (!input.confirmed) expect(d.action).not.toBe("write");
		// Unchanged is never a write.
		if (input.current === input.requested) expect(d.action).not.toBe("write");
		// A write is exactly: admin + confirmed + a real change, and it writes the request.
		if (d.action === "write") {
			expect(input.role).toBe("admin");
			expect(input.confirmed).toBe(true);
			expect(input.current).not.toBe(input.requested);
			expect(d.next).toBe(input.requested);
		}
		// Every write or confirmation request that turns it OFF carries the warning.
		if (
			input.role === "admin" &&
			!input.requested &&
			input.current !== input.requested
		)
			expect(d.warning).toBe(ACTION_CONTROL_OFF_WARNING);
		// Switching ON never carries the OFF warning.
		if (input.requested) expect(d.warning).toBeNull();
	});
});
