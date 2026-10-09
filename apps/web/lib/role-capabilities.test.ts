import { describe, expect, it } from "vitest";
import { roleCan } from "./role-capabilities.generated";

describe("roleCan (mirror of the gateway matrix)", () => {
	const cases: [
		string | null | undefined,
		boolean,
		boolean,
		boolean,
		boolean,
	][] = [
		// slug, manage_team, read_traces, view_spend, mint_keys
		["owner", true, true, true, true],
		["admin", true, true, true, true],
		["developer", false, true, true, true],
		["member", false, true, true, true],
		["viewer", false, true, true, false],
		["billing", false, false, true, false],
		["something-else", false, true, true, false],
		[null, false, true, true, false],
		[undefined, false, true, true, false],
	];
	for (const [slug, team, traces, spend, mint] of cases) {
		it(`${String(slug)}`, () => {
			expect(roleCan(slug, "manage_team")).toBe(team);
			expect(roleCan(slug, "read_traces")).toBe(traces);
			expect(roleCan(slug, "view_spend")).toBe(spend);
			expect(roleCan(slug, "mint_keys")).toBe(mint);
		});
	}
});
