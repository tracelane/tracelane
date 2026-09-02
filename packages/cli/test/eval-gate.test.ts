/**
 * EVL-30 — the CI eval gate's decision core.
 *
 * THE POINT OF THIS FILE: a CI gate that prints FAIL and exits 0 lets the bad
 * change merge. So the pairing of verdict to exit code is asserted EXHAUSTIVELY
 * rather than case by case — `decide()` is the only thing in the command that
 * chooses a verdict, an exit code or a printed line, and the table below is the
 * contract.
 *
 * There is deliberately NO baseline test, because there is no baseline (R246).
 * The gate asserts a floor on one run.
 */

import { describe, expect, it } from "vitest";
import {
	type RunScore,
	type Verdict,
	assertNoReservedFlags,
	decide,
	parseRunListing,
	parseSuiteFile,
	retiredSuiteMessage,
	scoreRun,
	validateFraction,
} from "../src/commands/eval.js";

const EXPECTED_EXIT: Record<Verdict, number> = {
	PASS: 0,
	FAIL: 1,
	"CANNOT-EVALUATE": 3,
};

const s = (
	meanScore: number | null,
	scoredCases: number,
	erroredCases = 0,
): RunScore => ({
	meanScore,
	scoredCases,
	erroredCases,
	totalCases: scoredCases + erroredCases,
});

describe("decide — verdict, exit code and PRINTED TEXT cannot disagree", () => {
	const cases: Array<[string, RunScore, number, number]> = [
		["all pass", s(1, 10), 0.9, 0.1],
		["all fail", s(0, 10), 0.9, 0.1],
		["all errored", s(null, 0, 10), 0.9, 0.1],
		["nothing at all", s(null, 0, 0), 0.9, 0.1],
		["exact tie", s(0.9, 10), 0.9, 0.1],
		["a hair under", s(0.899, 10), 0.9, 0.1],
		["errors over cap", s(1, 9, 5), 0.9, 0.1],
		["errors under cap", s(1, 19, 1), 0.9, 0.1],
		["threshold 0", s(0, 5), 0, 0.1],
		["threshold 1", s(1, 5), 1, 0.1],
	];
	for (const [label, score, threshold, cap] of cases) {
		it(`${label}: exit code matches the verdict, and something is printed`, () => {
			const d = decide(score, threshold, cap);
			expect(d.exitCode).toBe(EXPECTED_EXIT[d.verdict]);
			// `lines` IS the output. A verdict with nothing to print would mean
			// the caller has to format one itself, which is the seam R105 lives in.
			expect(d.lines.length).toBeGreaterThanOrEqual(1);
			expect(d.lines.some((l) => l.includes(d.verdict))).toBe(true);
		});
	}
});

describe("R246 — a FLOOR gate, and it must not claim to detect regressions", () => {
	it("never prints the word 'regression' in any verdict", () => {
		// A floor gate cannot detect a regression: 0.9 today and 0.85 tomorrow
		// both clear a 0.8 floor, and nothing here compared them. Copy asserting
		// a control the code does not implement is the class this repo has been
		// closing, and shipping it inside the feature that closes one would be
		// the seventh instance.
		const all: RunScore[] = [
			s(1, 4),
			s(0, 4),
			s(0.5, 4),
			s(null, 0, 4),
			s(1, 9, 5),
		];
		for (const score of all)
			for (const line of decide(score, 0.8, 0.1).lines)
				expect(line.toLowerCase()).not.toContain("regress");
	});

	it("has no baseline concept at all — decide takes exactly three arguments", () => {
		// Guards the deletion. A fourth parameter reappearing means someone has
		// reintroduced a comparison, which is R247's filed work and needs an ADR.
		expect(decide.length).toBe(3);
	});
});

describe("R244 — direction and ties, the two things the flag must state", () => {
	it("DIRECTION: the threshold is a FLOOR — below it fails, above it passes", () => {
		expect(decide(s(0.81, 10), 0.8, 0.1).verdict).toBe("PASS");
		expect(decide(s(0.79, 10), 0.8, 0.1).verdict).toBe("FAIL");
	});

	it("TIES PASS: score == threshold exits 0", () => {
		// A gate that fails on exactly the number you set is a gate nobody can
		// configure.
		const d = decide(s(0.8, 10), 0.8, 0.1);
		expect(d.verdict).toBe("PASS");
		expect(d.exitCode).toBe(0);
	});

	it("thresholds the MEAN SCORE, not the pass rate — they differ for a judge", () => {
		// Ten judge cases each scoring 0.85. A pass-rate gate would need a
		// per-case rule to turn those into pass/fail and would throw the
		// magnitude away; the mean keeps it, and 0.85 clears a 0.8 floor.
		expect(decide(s(0.85, 10), 0.8, 0.1).verdict).toBe("PASS");
		expect(decide(s(0.85, 10), 0.9, 0.1).verdict).toBe("FAIL");
	});
});

describe("below-the-floor vs could-not-measure — the distinction the gate is bought for", () => {
	it("errors are EXCLUDED from the mean, not scored as zero", () => {
		// 19 scored at 1.0, 1 errored. Folding the error in as a 0 would give
		// 0.95 and fail a 0.96 floor — a merge blocked by one provider 429.
		const d = decide(s(1, 19, 1), 0.96, 0.1);
		expect(d.verdict).toBe("PASS");
		expect(d.lines[0]).toContain("errored and excluded");
	});

	it("but too many errors is CANNOT-EVALUATE, not a pass", () => {
		// Exclusion must not become a laundering route: 9 cases at 1.0 is a
		// perfect mean, and without the cap this run would PASS while a third of
		// it never ran.
		const d = decide(s(1, 9, 5), 0.9, 0.1);
		expect(d.verdict).toBe("CANNOT-EVALUATE");
		expect(d.exitCode).toBe(3);
		expect(d.lines[0]).toContain("did not measure your prompt");
	});

	it("EVERY case errored is exit 3, never a vacuous pass", () => {
		const d = decide(s(null, 0, 10), 0.9, 1);
		expect(d.verdict).toBe("CANNOT-EVALUATE");
		expect(d.exitCode).toBe(3);
		expect(d.lines[0]).toContain("checked nothing");
	});

	it("a null mean with scored cases refuses rather than comparing null", () => {
		// Unreachable through `scoreRun`, asserted so a future caller cannot
		// reach `null >= threshold` and get a silent `false` == FAIL.
		const d = decide(
			{ meanScore: null, scoredCases: 3, erroredCases: 0, totalCases: 3 },
			0.5,
			0.1,
		);
		expect(d.verdict).toBe("CANNOT-EVALUATE");
	});

	it("the error cap is inclusive — exactly at it still evaluates", () => {
		expect(decide(s(1, 9, 1), 0.9, 0.1).verdict).toBe("PASS");
	});
});

describe("scoreRun — reducing a real results_json", () => {
	it("means the non-null case scores and counts the rest as errored", () => {
		const r = scoreRun({
			cases: [{ score: 1 }, { score: 0 }, { score: null }, {}],
		});
		expect(r.meanScore).toBe(0.5);
		expect(r.scoredCases).toBe(2);
		expect(r.erroredCases).toBe(2);
	});

	it("matches the shape prod actually returned", () => {
		// Verbatim from prod run 0b67da5f: four cases, boolean assertion, so the
		// mean IS the pass rate — which is why R244 changes nothing for
		// contains/exact_match/json_schema and everything for a judge.
		const r = scoreRun({
			cases: [{ score: 1.0 }, { score: 1.0 }, { score: 1.0 }, { score: 1.0 }],
			requested_cases: 4,
		});
		expect(r.meanScore).toBe(1);
		expect(r.erroredCases).toBe(0);
	});

	it("uses requested_cases when the run stopped early, so the error rate is honest", () => {
		// Two cases came back of four requested. Counting the denominator as 2
		// would report a 0% error rate on a run that dropped half its work.
		const r = scoreRun({ cases: [{ score: 1 }, { score: 1 }] }, 4);
		expect(r.totalCases).toBe(4);
		expect(r.erroredCases).toBe(2);
	});

	it("an empty or absent results block is scorable-zero, not a crash", () => {
		expect(scoreRun(null).scoredCases).toBe(0);
		expect(scoreRun({}).meanScore).toBeNull();
	});
});

describe("validateFraction — a usage error must never become a PASS", () => {
	it("accepts fractions including both bounds", () => {
		for (const ok of ["0", "0.5", "0.9", "1"])
			expect(validateFraction("--threshold", ok)).toBeNull();
	});

	it("REJECTS a percentage — 80 is not 80%", () => {
		expect(validateFraction("--threshold", "80")).toContain("FRACTION");
	});

	it("REJECTS non-numbers and negatives", () => {
		expect(validateFraction("--threshold", "high")).toContain("number");
		expect(validateFraction("--max-error-rate", "-0.1")).toContain("FRACTION");
	});
});

describe("parseSuiteFile — a gate that asserts nothing is not a gate", () => {
	it("REFUSES an empty assertions array", () => {
		// The gateway's scorer starts `all_passed = true` and never enters the
		// loop, so zero assertions marks every case Passed. That run reports a
		// perfect 1.000 and the gate goes green forever. `decide()` cannot see
		// the difference, so the refusal has to live here.
		expect(() => parseSuiteFile('{"assertions":[]}', "s.json")).toThrow(
			/0 assertions/,
		);
	});

	it("REFUSES a missing assertions array", () => {
		expect(() => parseSuiteFile('{"cases":[]}', "s.json")).toThrow(
			/no "assertions"/,
		);
	});

	it("REFUSES an empty cases array", () => {
		expect(() =>
			parseSuiteFile(
				'{"assertions":[{"kind":"contains"}],"cases":[]}',
				"s.json",
			),
		).toThrow(/0 cases/);
	});

	it("REFUSES a top-level array or unparseable JSON", () => {
		expect(() => parseSuiteFile("[]", "s.json")).toThrow(/JSON object/);
		expect(() => parseSuiteFile("{not json", "s.json")).toThrow(
			/not valid JSON/,
		);
	});

	it("accepts a well-formed suite", () => {
		const suite = parseSuiteFile(
			'{"assertions":[{"kind":"contains","value":"x"}],"model":"m"}',
			"s.json",
		);
		expect(suite.assertions).toHaveLength(1);
		expect(suite.model).toBe("m");
	});
});

describe("parseRunListing — an unrecognised shape is UNKNOWN, never empty", () => {
	it("reads the BARE ARRAY the endpoint actually returns", () => {
		// Verbatim shape from prod. Reading `body.runs` and falling back to `[]`
		// made a parse failure indistinguishable from an empty workspace — and
		// the caller printed the second with full confidence (B-306).
		expect(
			parseRunListing([{ eval_run_id: "a" }, { eval_run_id: "b" }]),
		).toHaveLength(2);
	});

	it("also accepts a {runs:[…]} wrapper, so a future change is not a silent zero", () => {
		expect(parseRunListing({ runs: [{ eval_run_id: "a" }] })).toHaveLength(1);
	});

	it("returns null — not [] — for a shape it does not recognise", () => {
		for (const junk of [null, undefined, {}, 42, "oops", { data: [] }])
			expect(parseRunListing(junk)).toBeNull();
	});

	it("an EMPTY array is a measured none, and stays distinct from null", () => {
		expect(parseRunListing([])).toEqual([]);
	});
});

describe("flag shadowing — the way a CI gate goes green having run nothing", () => {
	it("REFUSES --version, which commander reserves on the root program", () => {
		// Observed on prod during this feature's own proof: `--version <uuid>`
		// printed the CLI version and exited 0. The run never started.
		expect(() => assertNoReservedFlags(["--prompt", "--version"])).toThrow(
			/shadowed/,
		);
	});

	it("REFUSES --help for the same reason", () => {
		expect(() => assertNoReservedFlags(["--help"])).toThrow(/reserves/);
	});

	it("accepts the flags the command actually declares", () => {
		expect(() =>
			assertNoReservedFlags([
				"--prompt",
				"--env",
				"--version-id",
				"--dataset",
				"--snapshot",
				"--suite-file",
				"--threshold",
				"--max-error-rate",
				"--model",
				"--timeout",
				"--gateway",
				"--token",
				"--suite",
			]),
		).not.toThrow();
	});
});

describe("the retired repo-suite runner is loud, not silent", () => {
	it("names the replacement command and echoes the suite asked for", () => {
		expect(retiredSuiteMessage("pp")).toContain("pnpm eval:run --suite=pp");
		expect(retiredSuiteMessage(undefined)).toContain("--suite=all");
	});
});
