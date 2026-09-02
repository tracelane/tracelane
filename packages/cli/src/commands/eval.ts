/**
 * `tlane eval` — EVL-30, the CI eval gate.
 *
 *   tlane eval run   — run a suite or a frozen dataset against a prompt
 *                      version; exit non-zero when the mean score falls below
 *                      the `--threshold` floor.
 *   tlane eval list  — recent eval runs in this workspace.
 *
 * ## What this gate asserts, and what it does NOT (R246)
 *
 * **It asserts a FLOOR on a single run. It does not detect regressions.** There
 * is no baseline, no history and no comparison anywhere in this file: the same
 * shape as a coverage threshold, which nobody considers broken for lacking a
 * previous run.
 *
 * The word "regression" is kept out of every surface deliberately — the flag
 * help, the docs, the Action, this file. A floor gate cannot detect one, and
 * copy that asserts a control the code does not implement is the exact class
 * this repo has been closing. Comparing against an earlier run is a real gap
 * and is FILED, not built: "what IS the baseline — last run on main, a pinned
 * run, the previous run on this branch" is an ADR, not an afternoon.
 *
 * ## The exit code and the printed verdict come from ONE function
 *
 * `decide()` returns the verdict, the exit code AND the printed lines together.
 * A CI gate that prints FAIL and exits 0 lets the bad change merge, which is the
 * single worst thing this surface can do. A test asserts the pairing for every
 * verdict, so an edit that adds a verdict without an exit code fails.
 *
 * ## The comparison, stated rather than implied (R244)
 *
 * - DIRECTION: higher is better, and `--threshold` is a FLOOR.
 * - TIE: `score == threshold` PASSES. `>=`, not `>`.
 * - SCALE: a FRACTION in [0,1]. `--threshold 80` is rejected as a usage error
 *   rather than silently read as 8000%.
 *
 * ## "Below the floor" and "could not be measured" are different answers
 *
 * `meanScore` excludes errored cases rather than scoring them zero, and they are
 * bounded separately by `--max-error-rate` (default 0.10). One provider 429 in a
 * 20-case run is not a quality problem, and a gate that goes red on a 429 gets
 * deleted in a week. An unmeasurable run gets its own exit code (3).
 *
 * The safety property that survives the exclusion: a run where EVERY case
 * errored has `scoredCases == 0`, which is exit 3 — never a vacuous pass.
 *
 * ## A run with no assertions is refused, because it would pass forever
 *
 * `assertions` is `#[serde(default)]` on the gateway, and its scorer starts
 * `all_passed = true` and never enters the loop, so a run that asserts nothing
 * marks EVERY case `Passed`. The suite file's `assertions` array is therefore
 * required and must be non-empty; the refusal is a usage error (exit 2) at the
 * input, because `decide()` cannot tell a vacuous 1.000 from a real one.
 */

import { readFileSync } from "node:fs";
import process from "node:process";
import type { Command } from "commander";
import {
	type ConnOpts,
	apiGet,
	apiPost,
	renderApiError,
	resolveConn,
} from "../api.js";

// ── the decision core ────────────────────────────────────────────────────────

/**
 * What one finished run scored.
 *
 * `meanScore` is the mean of `results.cases[].score` over cases that produced
 * one. That per-case `score` is itself the mean of that case's scorer map, and
 * it is `null` when no scorer produced a value — a case whose provider call
 * failed, or whose every assertion errored.
 *
 * **Why the mean SCORE and not the pass RATE (R244).** For `contains`,
 * `exact_match` and `json_schema` the case score is exactly `1.0` or `0.0`, so
 * the mean IS the pass rate and nothing changes. For a judge it is continuous,
 * and there the two differ: a judge scoring 0.68 against a 0.70 rule and one
 * scoring 0.02 are the same `failed` and very different results. Thresholding
 * the rate throws that away; thresholding the mean keeps it.
 */
export interface RunScore {
	/** `null` when nothing was scorable. Never `0` for "we could not tell". */
	meanScore: number | null;
	scoredCases: number;
	erroredCases: number;
	totalCases: number;
}

export type Verdict = "PASS" | "FAIL" | "CANNOT-EVALUATE";

export interface Decision {
	verdict: Verdict;
	/** 0 PASS · 1 FAIL · 3 CANNOT-EVALUATE. Usage errors exit 2 earlier. */
	exitCode: 0 | 1 | 3;
	/** Every line the command prints, in order. See the note on `decide`. */
	lines: string[];
}

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
const num = (n: number) => n.toFixed(3);

/**
 * THE ONLY PLACE A VERDICT, AN EXIT CODE, OR A PRINTED LINE IS DECIDED.
 *
 * R105's class is a CI gate that prints FAIL and exits 0, which lets the bad
 * change merge — the exact inverse of the gate's purpose. The defence is that
 * the verdict, the exit code AND the text all leave this one pure function
 * together, in one object. The caller prints `lines` and exits `exitCode` and
 * has nothing else to get wrong: there is no second place that formats a
 * verdict, so there is nothing for the exit code to disagree with.
 *
 * ## THIS GATE ASSERTS A FLOOR. IT DOES NOT DETECT REGRESSIONS. (R246)
 *
 * There is no baseline, no history and no comparison anywhere in this file.
 * `--threshold 0.8` means "fail if THIS run's mean score is below 0.8" — the
 * same shape as a coverage threshold, which nobody considers broken for lacking
 * a previous run.
 *
 * **The word "regression" is deliberately absent from every surface**, and that
 * is a correctness rule rather than a style one: a floor gate cannot detect a
 * regression, and copy asserting a control the code does not implement is the
 * exact class this repo spent a week closing. A run that scores 0.9 today and
 * 0.85 tomorrow passes a 0.8 floor both times, and calling the second result
 * "no regression" would be a claim nothing here checked.
 *
 * Comparing a run to an earlier one is a real feature and a real gap; it is
 * filed, not built, because "what IS the baseline" is an ADR.
 *
 * ## The comparison (R244)
 *
 * - **DIRECTION: higher is better, and `--threshold` is a FLOOR.**
 * - **TIES PASS.** `score == threshold` exits 0. A gate that fails on exactly
 *   the number you set is a gate nobody can configure.
 */
export function decide(
	score: RunScore,
	threshold: number,
	maxErrorRate: number,
): Decision {
	if (score.scoredCases === 0) {
		return {
			verdict: "CANNOT-EVALUATE",
			exitCode: 3,
			lines: [
				`CANNOT-EVALUATE  0 of ${score.totalCases} cases produced a score (${score.erroredCases} errored) — the gate checked nothing. This is NOT a pass.`,
			],
		};
	}

	const errorRate =
		score.totalCases === 0 ? 0 : score.erroredCases / score.totalCases;
	if (errorRate > maxErrorRate) {
		return {
			verdict: "CANNOT-EVALUATE",
			exitCode: 3,
			lines: [
				`CANNOT-EVALUATE  ${pct(errorRate)} of cases errored (cap ${pct(maxErrorRate)}) — could not evaluate. The gate did not measure your prompt; raise --max-error-rate only if you have decided those errors are acceptable.`,
			],
		};
	}

	// `meanScore` is non-null whenever `scoredCases > 0`; the guard is here so a
	// future caller cannot reach the comparison with a null and get `false`.
	const mean = score.meanScore;
	if (mean === null)
		return {
			verdict: "CANNOT-EVALUATE",
			exitCode: 3,
			lines: [
				"CANNOT-EVALUATE  the run reported scored cases but no score — refusing " +
					"to guess a verdict from an uninterpretable result.",
			],
		};

	const tail =
		`mean score ${num(mean)} over ${score.scoredCases}/${score.totalCases} ` +
		`scored cases (${score.erroredCases} errored and excluded) vs ` +
		`threshold ${num(threshold)}`;

	// `>=`: a tie PASSES (R244), stated in this doc comment, in the flag's own
	// help text, and asserted in the tests.
	return mean >= threshold
		? {
				verdict: "PASS",
				exitCode: 0,
				lines: [`PASS  at or above the floor — ${tail}`],
			}
		: {
				verdict: "FAIL",
				exitCode: 1,
				lines: [`FAIL  below the floor — ${tail}`],
			};
}

/** Reduce a run's `results.cases[]` to the numbers `decide` needs. */
export function scoreRun(results: unknown, requested?: number): RunScore {
	const cases = ((results as { cases?: unknown[] } | null)?.cases ??
		[]) as Array<{ score?: number | null }>;
	const scored = cases
		.map((c) => c.score)
		.filter((s): s is number => typeof s === "number" && Number.isFinite(s));
	const totalCases = Math.max(cases.length, requested ?? 0);
	return {
		meanScore:
			scored.length === 0
				? null
				: scored.reduce((a, b) => a + b, 0) / scored.length,
		scoredCases: scored.length,
		erroredCases: totalCases - scored.length,
		totalCases,
	};
}

/** `--threshold` / `--max-error-rate` must be fractions. Returns an error, or null. */
export function validateFraction(flag: string, raw: string): string | null {
	const n = Number(raw);
	if (!Number.isFinite(n)) return `${flag} must be a number, got "${raw}"`;
	if (n < 0 || n > 1)
		return `${flag} is a FRACTION between 0 and 1, got ${raw}. Use 0.9 for 90% — a bare 90 is rejected rather than read as 9000%.`;
	return null;
}

// ── the suite file ───────────────────────────────────────────────────────────

export interface SuiteFile {
	assertions: unknown[];
	cases?: unknown[];
	model?: string;
	suite_name?: string;
}

/**
 * Parse and validate `--suite-file`.
 *
 * The assertions belong in the customer's repo next to the prompt, versioned
 * with it -- which is also why they are not a CLI flag.
 */
export function parseSuiteFile(text: string, path: string): SuiteFile {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch (e) {
		throw new Error(
			`${path} is not valid JSON (${e instanceof Error ? e.message : e})`,
		);
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
		throw new Error(`${path} must be a JSON object with an "assertions" array`);
	const o = parsed as Record<string, unknown>;
	if (!Array.isArray(o.assertions))
		throw new Error(`${path} has no "assertions" array`);
	if (o.assertions.length === 0)
		throw new Error(
			`${path} declares 0 assertions. A run with no assertions scores EVERY case as passed, so the gate would be green on the day the prompt breaks. Assert something, e.g. {"assertions":[{"kind":"contains","value":"..."}]}.`,
		);
	if (o.cases !== undefined && !Array.isArray(o.cases))
		throw new Error(`${path}: "cases" must be an array when present`);
	if (Array.isArray(o.cases) && o.cases.length === 0)
		throw new Error(
			`${path} declares 0 cases -- add "cases", or pass --dataset. A gate that passes with nothing to measure is the worst possible green.`,
		);
	return {
		assertions: o.assertions,
		cases: o.cases as unknown[] | undefined,
		model: typeof o.model === "string" ? o.model : undefined,
		suite_name: typeof o.suite_name === "string" ? o.suite_name : undefined,
	};
}

/** One row of the workspace-wide eval-run listing. */
export interface EvalRunSummary {
	eval_run_id: string;
	eval_suite_id: string;
	status: string;
	started_at_ms: number;
}

/**
 * Parse the run listing, returning `null` for a shape we do not recognise.
 *
 * **`null` and `[]` are different answers and must stay different (B-306).**
 * The endpoint returns a BARE ARRAY; the first implementation read `body.runs`
 * and fell back to `[]`, so a parse failure was indistinguishable from "this
 * workspace has no runs" — and the caller printed the second with full
 * confidence. `{runs: […]}` is accepted too, so a future wrapper does not
 * silently read as empty.
 */
export function parseRunListing(body: unknown): EvalRunSummary[] | null {
	if (Array.isArray(body)) return body as EvalRunSummary[];
	const wrapped = (body as { runs?: unknown })?.runs;
	if (Array.isArray(wrapped)) return wrapped as EvalRunSummary[];
	return null;
}

// ── talking to the gateway ───────────────────────────────────────────────────

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Everything that prevented a verdict, carrying the exit code it maps to. */
class Unmeasurable extends Error {
	constructor(
		message: string,
		readonly exitCode: 2 | 3,
	) {
		super(message);
	}
}

/**
 * Resolve `--dataset` as an id, else by EXACT name. Ambiguity is an error.
 *
 * **Uses the server-side `?name=` filter (R249), not a client-side scan.** The
 * listing is keyset-paginated at 200, so filtering a page here would find the
 * dataset only when it happens to be among the newest 200 — and report "no
 * dataset named …" for one that plainly exists otherwise. A wrong answer
 * manufactured by a paging boundary is worse than a slow one.
 */
async function resolveDatasetId(
	conn: ConnOpts,
	nameOrId: string,
): Promise<string> {
	if (UUID.test(nameOrId)) return nameOrId;
	const path = `/v1/datasets?name=${encodeURIComponent(nameOrId)}&limit=200`;
	const res = await apiGet<{
		datasets: { dataset_id: string; name: string }[];
	}>(conn, path);
	if (!res.ok)
		throw new Unmeasurable(renderApiError("GET", path, res).join("\n"), 3);
	const body = res.body as {
		datasets?: { dataset_id: string; name: string }[];
	};
	// `datasets` absent is an unrecognised shape, NOT an empty workspace — the
	// B-306 distinction. Reporting "no dataset named X" from a failed parse is a
	// confident claim about something we did not read.
	if (!Array.isArray(body.datasets))
		throw new Unmeasurable(
			"the gateway returned a dataset listing in a shape this CLI does not " +
				"recognise. Refusing rather than reporting 'no such dataset', which " +
				"would be a claim about data that was never read.",
			3,
		);
	// Belt and braces: the server filter is exact, and this re-checks it rather
	// than trusting the response to have honoured the parameter. A server that
	// ignored `?name=` would otherwise hand back page one and the first row
	// would silently become "the" match.
	const hits = body.datasets.filter((d) => d.name === nameOrId);
	const only = hits[0];
	if (hits.length === 1 && only) return only.dataset_id;
	if (hits.length === 0)
		throw new Unmeasurable(
			`no dataset named "${nameOrId}" in this workspace -- pass the dataset id`,
			2,
		);
	// Never guess: two datasets may legitimately share a name, and picking one
	// would make the gate's subject depend on list order.
	throw new Unmeasurable(
		`"${nameOrId}" matches ${hits.length} datasets -- pass the id instead: ${hits.map((d) => d.dataset_id).join(", ")}`,
		2,
	);
}

/** Resolve the prompt version: an explicit id wins, else the env pointer. */
async function resolveVersionId(
	conn: ConnOpts,
	prompt: string,
	versionId: string | undefined,
	env: string,
): Promise<string> {
	if (versionId) {
		if (!UUID.test(versionId))
			throw new Unmeasurable(`--version-id is not a uuid: ${versionId}`, 2);
		return versionId;
	}
	const path = `/v1/prompts/${encodeURIComponent(prompt)}?env=${encodeURIComponent(env)}`;
	const res = await apiGet<{ prompt_version_id: string }>(conn, path);
	if (!res.ok)
		throw new Unmeasurable(renderApiError("GET", path, res).join("\n"), 3);
	const id = (res.body as { prompt_version_id?: string }).prompt_version_id;
	if (!id)
		throw new Unmeasurable(
			`no version is routed to "${env}" for prompt "${prompt}" -- promote one, or pass --version-id`,
			2,
		);
	return id;
}

interface RunDetail {
	status: string;
	duration_ms?: number;
	results?: unknown;
	pass_count?: number;
	fail_count?: number;
	error_count?: number;
}

/** Start a run and poll to completion. */
async function runToCompletion(
	conn: ConnOpts,
	prompt: string,
	body: unknown,
	timeoutMs: number,
): Promise<RunDetail & { run_id: string; suite_id: string | null }> {
	const startPath = `/v1/prompts/${encodeURIComponent(prompt)}/evals`;
	const started = await apiPost<{
		eval_run_id?: string;
		run_id?: string;
		eval_suite_id?: string;
	}>(conn, startPath, body);
	if (!started.ok)
		throw new Unmeasurable(
			renderApiError("POST", startPath, started).join("\n"),
			// A 400 naming a limit or an unfrozen dataset is the caller's to fix;
			// anything else (auth, 409 collision, 5xx) is "could not evaluate".
			started.status === 400 || started.status === 404 ? 2 : 3,
		);
	const b = started.body as {
		eval_run_id?: string;
		run_id?: string;
		eval_suite_id?: string;
	};
	const runId = b.eval_run_id ?? b.run_id;
	if (!runId)
		throw new Unmeasurable(
			`the gateway started a run but returned no id: ${JSON.stringify(b)}`,
			3,
		);
	// Printed BEFORE polling, so a job killed by a CI timeout still leaves a
	// handle in the log.
	console.log(`tlane eval run: eval_run_id ${runId}`);

	const pollPath = `/v1/prompts/${encodeURIComponent(prompt)}/evals/${runId}`;
	const deadline = Date.now() + timeoutMs;
	let delay = 5000;
	for (;;) {
		const res = await apiGet<RunDetail>(conn, pollPath);
		if (!res.ok)
			throw new Unmeasurable(
				renderApiError("GET", pollPath, res).join("\n"),
				3,
			);
		const run = res.body as RunDetail;
		if (run.status !== "running")
			return { ...run, run_id: runId, suite_id: b.eval_suite_id ?? null };
		if (Date.now() > deadline)
			throw new Unmeasurable(
				`run ${runId} still 'running' after ${Math.round(timeoutMs / 1000)}s. The gate refuses to guess a verdict for an unfinished run; raise --timeout.`,
				3,
			);
		await new Promise((r) => setTimeout(r, delay));
		delay = Math.min(delay * 1.5, 15_000);
	}
}

// ── registration ─────────────────────────────────────────────────────────────

/**
 * Flags commander claims for itself on the root program.
 *
 * A subcommand that declares one of these is SHADOWED -- commander answers the
 * global first, prints its own output and exits 0. Observed on prod during this
 * feature's own proof: `--version <uuid>` printed the CLI version and exited 0
 * without starting a run. For a CI gate that is the worst possible failure:
 * green, silent, and having checked nothing. Hence `--version-id`.
 */
export const RESERVED_FLAGS = ["--version", "--help"] as const;

/** Throws if any option name collides with a commander global. */
export function assertNoReservedFlags(flags: string[]): void {
	const clash = flags.filter((f) =>
		(RESERVED_FLAGS as readonly string[]).includes(f),
	);
	if (clash.length > 0)
		throw new Error(
			`eval run declares ${clash.join(", ")}, which commander reserves on the root program. The subcommand flag is shadowed and the gate exits 0 without running. Rename it (e.g. --version-id).`,
		);
}

/** The message the retired repo-suite runner leaves behind. Exit 2, never silent. */
export function retiredSuiteMessage(suite: string | undefined): string {
	const s = suite ?? "all";
	return `\`tlane eval run\` now runs a gateway eval suite and needs --prompt and --threshold. To run Tracelane's own conformance suite from a clone: pnpm eval:run --suite=${s}`;
}

export function registerEvalCommand(program: Command): void {
	const evalCmd = program
		.command("eval")
		.description("Gateway eval runs: the CI gate, and recent runs");

	const run = evalCmd
		.command("run")
		.description(
			"Run a suite or frozen dataset against a prompt version; exit non-zero below --threshold",
		)
		.requiredOption("--prompt <name>", "Prompt name to evaluate")
		.option("--env <env>", "Resolve the version routed to this env", "staging")
		.option("--version-id <uuid>", "Pin an exact prompt version id")
		.option("--dataset <nameOrId>", "Frozen dataset to draw cases from")
		.option("--snapshot <id>", "Pin a snapshot; default is the newest")
		.option(
			"--suite-file <path>",
			"JSON file holding `assertions` (and optionally `cases`)",
		)
		// R244: DIRECTION and TIE behaviour live in the flag's own help text, not
		// only in the docs. The flag is the surface — a customer configuring a
		// merge gate reads `--help`, and a tie rule they have to find in a doc
		// site is a tie rule they will guess at.
		.requiredOption(
			"--threshold <fraction>",
			"FLOOR on the mean score, 0..1. Higher is better: FAILS if the mean " +
				"score is BELOW this. A TIE PASSES — score == threshold exits 0. " +
				"0.8 means 80%; a bare 80 is rejected, not read as 8000%",
		)
		.option(
			"--max-error-rate <fraction>",
			"CEILING on the errored fraction, 0..1. Above it the verdict is " +
				"cannot-evaluate (exit 3) — the gate did not measure your prompt, which is not the same as it failing",
			"0.10",
		)
		.option("--model <model>", "Override the version's model pin")
		.option("--timeout <seconds>", "How long to wait for the run", "1800")
		.option("--gateway <url>", "Gateway base URL")
		.option(
			"--token <token>",
			"API token (or TRACELANE_TOKEN / TRACELANE_API_KEY)",
		)
		// Registered as a TOMBSTONE so the old invocation errors with a pointer
		// instead of commander's bare `unknown option`. Deliberately NOT reused
		// for the new suite label -- silently repurposing a flag is how a
		// workflow keeps passing while measuring something else.
		.option("--suite <name>", "RETIRED -- see the message it prints")
		.action(async (opts) => {
			if (opts.suite !== undefined) {
				console.error(`tlane eval run: ${retiredSuiteMessage(opts.suite)}`);
				process.exit(2);
			}
			for (const [flag, raw] of [
				["--threshold", opts.threshold],
				["--max-error-rate", opts.maxErrorRate],
			] as const) {
				const bad = validateFraction(flag, raw);
				if (bad) {
					// Usage errors exit 2 and NEVER reach `decide()` -- a malformed
					// threshold must not be able to produce a PASS.
					console.error(`tlane eval run: ${bad}`);
					process.exit(2);
				}
			}
			if (!opts.dataset && !opts.suiteFile) {
				console.error(
					"tlane eval run: pass --dataset <name> or --suite-file <path> -- " +
						"there is nothing to run cases from.",
				);
				process.exit(2);
			}
			const threshold = Number(opts.threshold);
			const maxErrorRate = Number(opts.maxErrorRate);

			let suite: SuiteFile | null = null;
			if (opts.suiteFile) {
				try {
					suite = parseSuiteFile(
						readFileSync(opts.suiteFile, "utf8"),
						opts.suiteFile,
					);
				} catch (e) {
					console.error(
						`tlane eval run: ${e instanceof Error ? e.message : String(e)}`,
					);
					process.exit(2);
				}
			}
			// A dataset run still needs assertions, and they only live in the
			// suite file. Refused here rather than discovered as a vacuous 100%.
			if (opts.dataset && !suite) {
				console.error(
					"tlane eval run: --dataset needs --suite-file for its `assertions`. " +
						"A run with no assertions scores every case as passed.",
				);
				process.exit(2);
			}

			const conn = resolveConn(opts);
			try {
				const versionId = await resolveVersionId(
					conn,
					opts.prompt,
					opts.versionId,
					opts.env,
				);
				const cases = opts.dataset
					? {
							source: "dataset",
							dataset_id: await resolveDatasetId(conn, opts.dataset),
							...(opts.snapshot ? { snapshot_id: opts.snapshot } : {}),
						}
					: { source: "inline", items: suite?.cases ?? [] };
				const model = opts.model ?? suite?.model;
				const runRes = await runToCompletion(
					conn,
					opts.prompt,
					{
						prompt_version_id: versionId,
						cases,
						assertions: suite?.assertions ?? [],
						...(suite?.suite_name ? { suite_name: suite.suite_name } : {}),
						...(model ? { model } : {}),
					},
					Number(opts.timeout) * 1000,
				);
				const results = (runRes as { results?: unknown }).results;
				const requested = (results as { requested_cases?: number } | null)
					?.requested_cases;
				const scored = scoreRun(results, requested);
				const d = decide(scored, threshold, maxErrorRate);
				// ONE print, ONE exit, BOTH from `d` — `d.lines` is the whole output,
				// so there is no second place that formats a verdict and therefore
				// nothing for the exit code to disagree with (R105).
				for (const line of d.lines) console.log(`tlane eval run: ${line}`);
				console.log(
					`tlane eval run: run ${runRes.run_id} (status ${runRes.status}` +
						`${runRes.duration_ms ? `, ${(runRes.duration_ms / 1000).toFixed(1)}s` : ""})`,
				);
				process.exit(d.exitCode);
			} catch (err) {
				const code = err instanceof Unmeasurable ? err.exitCode : 3;
				// Anything that prevented a verdict is CANNOT-EVALUATE (3) unless it
				// is the caller's own invocation (2). Never 0, and never 1: "the
				// gateway was down" is not "your prompt scored below the floor".
				console.error(
					`tlane eval run: ${code === 3 ? "CANNOT-EVALUATE" : "USAGE"} -- ` +
						`${err instanceof Error ? err.message : String(err)}`,
				);
				process.exit(code);
			}
		});

	assertNoReservedFlags(run.options.map((o) => o.long ?? ""));

	evalCmd
		.command("list")
		.description("Recent eval runs in this workspace")
		.option("--limit <n>", "How many to show (server caps at 200)", "20")
		.option("--gateway <url>", "Gateway base URL")
		.option(
			"--token <token>",
			"API token (or TRACELANE_TOKEN / TRACELANE_API_KEY)",
		)
		.action(async (opts) => {
			const conn = resolveConn(opts);
			// `list_evals_handler` ignores the prompt name in its path, so the
			// listing is workspace-wide and this command takes no prompt argument.
			const path = `/v1/prompts/_/evals?limit=${encodeURIComponent(opts.limit)}`;
			const res = await apiGet<unknown>(conn, path);
			if (!res.ok) {
				console.error(renderApiError("GET", path, res).join("\n"));
				process.exit(3);
			}
			// `parseRunListing`, for the reason B-306 records: this
			// endpoint returns a bare array, and a `?? []` here would have
			// printed "0 runs" against a workspace full of them.
			const runs = parseRunListing(res.body) as
				| Record<string, unknown>[]
				| null;
			if (runs === null) {
				console.error(
					"tlane eval list: the gateway returned a run listing in a shape " +
						"this CLI does not recognise. Reporting nothing rather than " +
						"an empty list, which would read as 'you have no runs'.",
				);
				process.exit(3);
			}
			for (const r of runs)
				console.log(
					[
						String(r.eval_run_id ?? "-").padEnd(38),
						String(r.status ?? "-").padEnd(9),
						`${r.pass_count ?? 0}p/${r.fail_count ?? 0}f/${r.error_count ?? 0}e`,
					].join(" "),
				);
			console.log(`\n${runs.length} runs (server cap 200)`);
		});
}
