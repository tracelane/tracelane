/**
 * ACT-22 — coverage is derived only from what was read; it never claims protection it could not
 * confirm. Negative cases first.
 */
import { describe, expect, it } from "vitest";
import {
	COVERAGE_NOTE,
	MAX_ROWS,
	type PolicyRef,
	type SeenTool,
	buildCoverage,
	protectedFlagOf,
} from "./coverage";

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";
const seen = (
	server_id: string,
	tool_name: string,
	server_name = "Pay",
): SeenTool => ({
	server_id,
	server_name,
	tool_name,
});
const pol = (n: number, server_id: string, tool_name: string): PolicyRef => ({
	tool_ref: `ref-${n}`,
	server_id,
	tool_name,
});

describe("never overclaims protection", () => {
	it("a seen tool with no policy is observed only", () => {
		const c = buildCoverage([seen(S1, "a")], [], {});
		expect(c.rows[0]?.state).toBe("observed");
		expect(c.protectedCount).toBe(0);
	});
	it("a policy whose contract could not be read is unchecked, not protected", () => {
		const c = buildCoverage([seen(S1, "a")], [pol(1, S1, "a")], {});
		expect(c.rows[0]?.state).toBe("unchecked");
		expect(c.protectedCount).toBe(0);
		expect(c.sentence).toMatch(/1 could not be checked/);
	});
	it("a policy on a contract with protected=false is observed only", () => {
		const c = buildCoverage([seen(S1, "a")], [pol(1, S1, "a")], {
			"ref-1": false,
		});
		expect(c.rows[0]?.state).toBe("observed");
	});
	it("the same tool name on another server is not covered by this policy", () => {
		const c = buildCoverage([seen(S2, "a", "Other")], [pol(1, S1, "a")], {
			"ref-1": true,
		});
		const other = c.rows.find((r) => r.server === "Other");
		expect(other?.state).toBe("observed");
	});
	it("empty inputs say nothing has been seen, not that everything is protected", () => {
		const c = buildCoverage([], [], {});
		expect(c.sentence).toBe("No tools have been seen through Tracelane yet.");
		expect(c.total).toBe(0);
	});
	it("a seen tool is never counted twice for several definitions", () => {
		const c = buildCoverage(
			[seen(S1, "a"), seen(S1, "a"), seen(S1, "a")],
			[],
			{},
		);
		expect(c.total).toBe(1);
	});
	it("a protected tool never seen is listed as not seen", () => {
		const c = buildCoverage([], [pol(1, S1, "a")], { "ref-1": true });
		expect(c.rows[0]).toMatchObject({ state: "protected", seen: false });
	});
	it("truncates beyond the cap and says so", () => {
		const many = Array.from({ length: MAX_ROWS + 5 }, (_, i) =>
			seen(S1, `t${i}`),
		);
		const c = buildCoverage(many, [], {});
		expect(c.rows).toHaveLength(MAX_ROWS);
		expect(c.truncated).toBe(true);
		expect(c.total).toBe(MAX_ROWS + 5);
	});
	it("the fixed note is the required sentence", () => {
		expect(COVERAGE_NOTE).toBe(
			"Calls that do not go through Tracelane are not seen.",
		);
	});
});

describe("protectedFlagOf", () => {
	it.each([
		["true", '{"protected":true}', true],
		["false", '{"protected":false}', false],
		["missing", "{}", undefined],
		["string true", '{"protected":"true"}', undefined],
		["bad json", "{", undefined],
		["not a string", 5, undefined],
		["null", null, undefined],
	])("%s", (_n, input, want) => {
		expect(protectedFlagOf(input)).toBe(want);
	});
});

describe("counts and ordering", () => {
	const c = buildCoverage(
		[seen(S1, "pay"), seen(S1, "read"), seen(S2, "export", "Data")],
		[pol(1, S1, "pay"), pol(2, S2, "export")],
		{ "ref-1": true, "ref-2": true },
	);
	it("counts protected and total", () => {
		expect(c.protectedCount).toBe(2);
		expect(c.total).toBe(3);
	});
	it("answer-first sentence", () => {
		expect(c.sentence).toBe(
			"2 of 3 tools seen through Tracelane are protected; the rest are observed only.",
		);
	});
	it("lists protected first, observed last", () => {
		expect(c.rows.map((r) => r.state)).toEqual([
			"protected",
			"protected",
			"observed",
		]);
	});
	it("singular wording", () => {
		const one = buildCoverage([seen(S1, "a")], [pol(1, S1, "a")], {
			"ref-1": true,
		});
		expect(one.sentence).toMatch(
			/^1 of 1 tool seen through Tracelane is protected/,
		);
	});
	it("an unnamed server gets a plain label", () => {
		const r = buildCoverage([{ server_id: S1, tool_name: "a" }], [], {});
		expect(r.rows[0]?.server).toBe("Unnamed server");
	});
	it("visible strings carry no internal ids", () => {
		const text = JSON.stringify([c.sentence, COVERAGE_NOTE]);
		expect(text).not.toMatch(/\b(ACT|SRE|ADR)-\d+|tenant|org_/i);
	});
});

describe("invariant sweep — states x flags", () => {
	const flagCases: [boolean | undefined, string][] = [
		[true, "protected"],
		[false, "observed"],
		[undefined, "unchecked"],
	];
	for (const hasSeen of [true, false])
		for (const hasPolicy of [true, false])
			for (const [flag, want] of flagCases) {
				if (!hasSeen && !hasPolicy) continue;
				it(`seen=${hasSeen} policy=${hasPolicy} flag=${flag}`, () => {
					const c = buildCoverage(
						hasSeen ? [seen(S1, "a")] : [],
						hasPolicy ? [pol(1, S1, "a")] : [],
						{ "ref-1": flag },
					);
					const row = c.rows[0];
					expect(row?.state).toBe(hasPolicy ? want : "observed");
					// Protected requires a policy AND a readable protected=true.
					if (row?.state === "protected") {
						expect(hasPolicy && flag === true).toBe(true);
					}
				});
			}
});
