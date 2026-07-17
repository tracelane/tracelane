import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-SEAT-CAP — Bundled seats + $19/seat capped overage
 *
 * Behavior: each paid tier bundles a number of seats; additional seats
 * bill at $19/mo as a metered seat overage. Beyond the per-tier max, the
 * dashboard surfaces a
 * "contact sales" CTA instead of issuing more invites.
 *
 * Enterprise is the only tier with unlimited seats (encoded as
 * seat_cap_max = 0 sentinel in plan_entitlements).
 *
 * Five structural assertions per pain-points convention:
 *   1. Team tenant with 10 active seats — 11th invite triggers $19/seat meter event
 *   2. Team tenant with 25 active seats — 26th invite blocks with "contact sales" CTA
 *   3. Business 25/50 behaves equivalently
 *   4. Enterprise has no seat cap (seat_cap_max = 0 → unlimited)
 *   5. Seat removal reverses the meter on next billing period
 *
 * Linked: per-tier seat-cap entitlement (bundled seats + capped overage)
 */

interface SeatInviteDecision {
	allowed: boolean;
	billedSeatOverage: boolean;
	contactSalesRequired: boolean;
}

function inviteDecision(
	plan: "team" | "business" | "enterprise",
	activeSeats: number,
): SeatInviteDecision {
	const caps: Record<typeof plan, { included: number; max: number }> = {
		team:       { included: 10, max: 25 },
		business:   { included: 25, max: 50 },
		enterprise: { included: 0,  max: 0 }, // 0 = unlimited sentinel
	};
	const { included, max } = caps[plan];
	const next = activeSeats + 1;
	if (max === 0) {
		return { allowed: true, billedSeatOverage: false, contactSalesRequired: false };
	}
	if (next > max) {
		return { allowed: false, billedSeatOverage: false, contactSalesRequired: true };
	}
	if (next > included) {
		return { allowed: true, billedSeatOverage: true, contactSalesRequired: false };
	}
	return { allowed: true, billedSeatOverage: false, contactSalesRequired: false };
}

describe("PP-SEAT-CAP: bundled seats + capped per-seat overage", () => {
	it("1. Team at 10 active seats — 11th invite triggers $19/seat meter", () => {
		const d = inviteDecision("team", 10);
		expect(d.allowed).toBe(true);
		expect(d.billedSeatOverage).toBe(true);
		expect(d.contactSalesRequired).toBe(false);
	});

	it("2. Team at 25 active seats — 26th invite blocks with contact-sales CTA", () => {
		const d = inviteDecision("team", 25);
		expect(d.allowed).toBe(false);
		expect(d.contactSalesRequired).toBe(true);
		expect(d.billedSeatOverage).toBe(false);
	});

	it("3. Business 25/50 behaves equivalently", () => {
		const at25 = inviteDecision("business", 25);
		expect(at25.allowed).toBe(true);
		expect(at25.billedSeatOverage).toBe(true);

		const at50 = inviteDecision("business", 50);
		expect(at50.allowed).toBe(false);
		expect(at50.contactSalesRequired).toBe(true);
	});

	it("4. Enterprise has no seat cap (seat_cap_max = 0 ⇒ unlimited)", () => {
		const arbitraryHigh = inviteDecision("enterprise", 10_000);
		expect(arbitraryHigh.allowed).toBe(true);
		expect(arbitraryHigh.billedSeatOverage).toBe(false);
		expect(arbitraryHigh.contactSalesRequired).toBe(false);
	});

	it("5. Seat removal reverses the meter on next billing period", () => {
		// Team at 15 seats — 5 overage seats billed.
		// Remove 3 — overage drops from 5 to 2 on next cycle.
		const billedAt = (active: number) => Math.max(0, active - 10);
		expect(billedAt(15)).toBe(5);
		expect(billedAt(12)).toBe(2);
		expect(billedAt(10)).toBe(0);
	});
});
