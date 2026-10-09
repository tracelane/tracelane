/**
 * rev4 L6 (2026-10-03): `seed.mjs` must REFUSE a B-409 allowance drift BEFORE it
 * writes anything.
 *
 * The seed used to rewrite `plan_entitlements` (prices, allowances, flags) and only
 * then discover that `plans.v3.json` changed a pinned version's numbers in place —
 * throwing half-way and leaving the catalog on the NEW ruling while
 * `plan_allowances` still said the OLD one. A refusal that lands after the writes is
 * a half-applied seed, not a refusal.
 *
 * `seed.mjs` is a top-level-await script against Neon's HTTP driver, so it is read
 * here as source (the same way `components/guardrails/rail-tier-drift.test.ts`
 * reads it): the drift CHECK must appear before the first statement that writes.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const SEED = readFileSync(new URL("./seed.mjs", import.meta.url), "utf8");

/** Offset of the first tagged-template SQL statement that writes a table. */
function firstWrite(src: string): number {
	const re =
		/sql`\s*(insert\s+into|update\s+\w+\s+set|delete\s+from|truncate)\b/gi;
	const m = re.exec(src);
	return m ? m.index : -1;
}

describe("seed.mjs — B-409 drift is refused before any write (rev4 L6)", () => {
	it("the plan_allowances drift check runs before the first write statement", () => {
		// The CALL, not the definition — a definition at the top proves nothing.
		const check = SEED.indexOf("await assertAllowanceVersionUnchanged()");
		const write = firstWrite(SEED);
		expect(write, "the seed writes something").toBeGreaterThan(0);
		expect(check, "the pre-write drift check exists").toBeGreaterThan(0);
		expect(
			check,
			"the drift check must run BEFORE the first write — a refusal after the writes is a half-applied seed",
		).toBeLessThan(write);
	});
});
