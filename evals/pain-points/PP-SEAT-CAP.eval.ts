import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-SEAT-CAP — seats are a per-tier HARD CAP, never a purchasable ladder.
 *
 * REWRITTEN 2026-08-12 when the ADR-020 seat amendment was accepted. The previous
 * version of this file asserted the opposite of what ships, and did it against
 * nothing: it defined a local `inviteDecision()` helper inside the eval and then
 * tested that helper. Its headline case was
 *
 *     "1. Team at 10 active seats — 11th invite triggers $19/seat meter"
 *
 * for a $19/seat meter that **was never built, sold, or billed**, whose two Polar
 * products were retired on 2026-08-08. The eval was green the entire time,
 * because a self-contained model of a fictional feature always is. That is the
 * vanity-eval shape: structural, passing, and asserting something false.
 *
 * So this file now reads the REAL source and asserts the amendment:
 *   1. the invite route hard-refuses at the cap with 403 `seat_limit_reached`
 *   2. seat usage counts accepted members PLUS pending invitations
 *   3. the caps are 1 / 1 / 25 / 50 / 0-unlimited, from ONE source of truth
 *   4. the retired extra-seat lookup keys are recognised but NOT granted (tripwire)
 *   5. no $19/seat meter exists anywhere in the tree
 *   6. the cap reads as an upgrade path, not a raw error token (condition A)
 *
 * Linked: ADR-020 amendment 2026-08-12 (accepted).
 */
function read(rel: string): string {
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const fs = require("node:fs");
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const path = require("node:path");
	return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

const INVITE_ROUTE = "../../apps/web/app/api/settings/team/invite/route.ts";
const ENTITLEMENTS = "../../apps/web/lib/entitlements.ts";
const POLAR_WEBHOOK = "../../apps/web/app/api/webhooks/polar/route.ts";
/** Where the retired keys are actually RECOGNISED — not the route (see case 4). */
const POLAR_KEYS = "../../apps/web/lib/polar-webhook.ts";
const TEAM_UI = "../../apps/web/components/settings/TeamManager.tsx";

describe("PP-SEAT-CAP: seats are a hard cap, not a ladder (ADR-020 amendment)", () => {
	it("1. the invite route REFUSES at the cap with 403 seat_limit_reached", () => {
		const src = read(INVITE_ROUTE);
		expect(src).toContain("seat_limit_reached");
		expect(src).toContain("seat_cap_max");
		expect(src).toContain("upgrade_url");
		// The refusal must be a 403, not a soft warning that still invites.
		expect(/status:\s*403/.test(src), "refusal must be HTTP 403").toBe(true);
	});

	it("2. seat usage counts accepted members PLUS pending invitations", () => {
		const src = read(INVITE_ROUTE);
		// Both reserve a seat; counting only accepted members lets a workspace
		// exceed its cap by inviting faster than people accept.
		expect(
			/members\.length\s*\+\s*pendingInvites\.length/.test(src),
			"usage must be members + pending invitations",
		).toBe(true);
	});

	it("3. caps are 1/1/25/50/0-unlimited from ONE source of truth", () => {
		const src = read(ENTITLEMENTS);
		const caps = [...src.matchAll(/seat_cap_max:\s*(\d+)/g)].map((m) =>
			Number(m[1]),
		);
		// free, builder, team, business, enterprise — in plan order.
		expect(caps.slice(0, 5).join(",")).toBe("1,1,25,50,0");
		expect(src).toContain("0 sentinel = unlimited");
		// The gate must read the same resolved field the display reads. A separate
		// UI-only map is how this drifted once already.
		expect(read(INVITE_ROUTE)).toContain("entitlements.seat_cap_max");
	});

	it("4. TRIPWIRE: retired extra-seat keys are recognised but NOT granted", () => {
		// The tripwire is TWO files, and the draft amendment cited only the route.
		// This case caught that on its first run: recognition lives in
		// lib/polar-webhook.ts, non-wiring in the route handler.
		const keys = read(POLAR_KEYS);
		for (const key of ["team_extra_seat_v1", "business_extra_seat_v1"]) {
			expect(keys, `${key} must still be RECOGNISED as a tripwire`).toContain(
				key,
			);
		}
		// Deliberately not wired: a manually created seat purchase must change
		// nothing, and must be LOUD rather than silently unknown.
		const route = read(POLAR_WEBHOOK);
		expect(
			/grant NOT auto-wired/.test(route),
			"a recognised-but-unwired add-on must say so loudly",
		).toBe(true);
	});

	it("5. no $19/seat overage meter exists anywhere on the seat path", () => {
		// The claim the old eval asserted. If a per-seat meter is ever
		// re-introduced, it lands here first and this fails.
		for (const f of [INVITE_ROUTE, POLAR_WEBHOOK, ENTITLEMENTS]) {
			const src = read(f);
			expect(
				/seat[_-]?overage|per[_-]?seat[_-]?meter|19\s*\/\s*seat/i.test(src),
				`${f} must contain no per-seat overage path`,
			).toBe(false);
		}
	});

	it("6. condition A — the cap reads as an upgrade path, not a raw token", () => {
		const ui = read(TEAM_UI);
		// Before 2026-08-12 this surface rendered the literal string
		// `seat_limit_reached` at the user, having discarded seat_cap_max/used/
		// upgrade_url. A machine token is a wall; a sentence with a route is not.
		expect(ui).toContain("seat_limit_reached");
		expect(ui).toContain("Seats are not sold individually");
		expect(ui).toContain("/settings/billing");
		// And it must NOT promise a per-seat purchase, which would re-create the
		// expectation the amendment exists to forbid.
		expect(
			/buy (?:more )?seats|purchase seats|add seats for/i.test(ui),
			"copy must not imply seats are purchasable",
		).toBe(false);
	});
});
