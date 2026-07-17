import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

/** Shape of the slice of k6's `--summary-export` JSON we consume. */
interface K6Summary {
	metrics?: Record<string, { values?: Record<string, number> }>;
}

// ── Eval harness types ────────────────────────────────────────────────────────

export interface PainPointConfig<TSetup, TResult> {
	id: string;
	title: string;
	competitorBehavior: string;
	pain: string;
	setup: () => Promise<TSetup>;
	run: (ctx: TSetup) => Promise<TResult>;
	assert: (result: TResult) => void;
	teardown?: (ctx: TSetup) => Promise<void>;
}

export interface EvalResult {
	id: string;
	title: string;
	status: "pass" | "fail" | "skip";
	durationMs: number;
	error?: string;
}

const results: EvalResult[] = [];

/**
 * Register and immediately run a pain-point eval.
 * In CI (TRACELANE_EVAL_MOCK_PROVIDERS=true) all evals that require
 * a live gateway are run against the mock provider.
 */
export async function painPoint<TSetup, TResult>(
	config: PainPointConfig<TSetup, TResult>,
): Promise<EvalResult> {
	const start = Date.now();
	let ctx: TSetup | undefined;

	try {
		ctx = await config.setup();
		const result = await config.run(ctx);
		config.assert(result);

		const r: EvalResult = {
			id: config.id,
			title: config.title,
			status: "pass",
			durationMs: Date.now() - start,
		};
		results.push(r);
		return r;
	} catch (err) {
		const r: EvalResult = {
			id: config.id,
			title: config.title,
			status: "fail",
			durationMs: Date.now() - start,
			error: err instanceof Error ? err.message : String(err),
		};
		results.push(r);
		throw err;
	} finally {
		if (ctx && config.teardown) {
			await config.teardown(ctx).catch(() => {});
		}
	}
}

export function getAllResults(): EvalResult[] {
	return [...results];
}

// ── Assertion helpers ─────────────────────────────────────────────────────────

export function expect<T>(value: T, message?: string): Expectations<T> {
	return new Expectations(value, false, message);
}

// Vitest-compatibility shim: `expect.fail(reason)` throws an error with the
// given reason. Used by scaffold evals that want to mark an assertion as
// "wired in a later session" without faking a pass.
expect.fail = (reason: string): never => {
	throw new Error(reason);
};

export class Expectations<T> {
	constructor(
		private readonly value: T,
		private readonly negated = false,
		private readonly customMessage?: string,
	) {}

	get not(): Expectations<T> {
		return new Expectations(this.value, !this.negated, this.customMessage);
	}

	private pass(condition: boolean, message: string): void {
		if (this.negated ? condition : !condition) {
			const base = this.negated ? `Expected NOT: ${message}` : message;
			const full = this.customMessage ? `${this.customMessage}: ${base}` : base;
			throw new Error(full);
		}
	}

	toBe(expected: T): void {
		this.pass(
			this.value === expected,
			`Expected ${JSON.stringify(this.value)} to be ${JSON.stringify(expected)}`,
		);
	}

	toBeLessThan(n: number): void {
		this.pass(
			typeof this.value === "number" && this.value < n,
			`Expected ${this.value} to be less than ${n}`,
		);
	}

	toBeGreaterThan(n: number): void {
		this.pass(
			typeof this.value === "number" && this.value > n,
			`Expected ${this.value} to be greater than ${n}`,
		);
	}

	toBeGreaterThanOrEqual(n: number): void {
		this.pass(
			typeof this.value === "number" && this.value >= n,
			`Expected ${this.value} to be >= ${n}`,
		);
	}

	toBeLessThanOrEqual(n: number): void {
		this.pass(
			typeof this.value === "number" && this.value <= n,
			`Expected ${this.value} to be <= ${n}`,
		);
	}

	toBeDefined(): void {
		this.pass(
			this.value !== undefined && this.value !== null,
			`Expected value to be defined, got ${this.value}`,
		);
	}

	toBeUndefined(): void {
		this.pass(
			this.value === undefined,
			`Expected value to be undefined, got ${this.value}`,
		);
	}

	toContain(expected: unknown): void {
		if (typeof this.value === "string") {
			this.pass(
				this.value.includes(expected as string),
				`Expected string to contain ${JSON.stringify(expected)}\nReceived: ${JSON.stringify((this.value as string).slice(0, 200))}`,
			);
		} else if (Array.isArray(this.value)) {
			this.pass(
				(this.value as unknown[]).includes(expected),
				`Expected array to contain ${JSON.stringify(expected)}`,
			);
		} else {
			throw new Error(`toContain is not supported for ${typeof this.value}`);
		}
	}

	toHaveLength(expected: number): void {
		const len = (this.value as { length: number }).length;
		this.pass(len === expected, `Expected length ${expected}, got ${len}`);
	}

	toMatch(pattern: string | RegExp): void {
		if (typeof this.value !== "string") {
			throw new Error(
				`toMatch requires a string value, got ${typeof this.value}`,
			);
		}
		const re = typeof pattern === "string" ? new RegExp(pattern) : pattern;
		this.pass(
			re.test(this.value),
			`Expected string to match ${re}\nReceived: ${JSON.stringify((this.value as string).slice(0, 200))}`,
		);
	}
}

// ── Live-gateway gating ───────────────────────────────────────────────────────

/**
 * Sentinel thrown by performance/live helpers (`runK6`, `spawnGateway`) when
 * no real gateway is configured. Eval files catch this and convert it into a
 * vitest skip, so a perf assertion that measures nothing reports as **skipped**
 * — never as a fabricated "pass".
 */
export class LiveGatewayUnavailableError extends Error {
	constructor(reason: string) {
		super(reason);
		this.name = "LiveGatewayUnavailableError";
	}
}

/**
 * True only when an operator has explicitly pointed the suite at a real
 * gateway. This is the single source of truth for "may we measure real
 * performance?". CI sets neither var, so this is `false` in CI and the
 * perf evals skip honestly.
 *
 * Activation (mirror of live-harness.ts):
 *   - `TRACELANE_EVAL_LIVE_GATEWAY_URL` set, OR
 *   - `TRACELANE_EVAL_SPAWN_GATEWAY=1`
 *
 * Note: the legacy `TRACELANE_EVAL_MOCK_PROVIDERS=false` flag no longer
 * unlocks fabricated numbers; it is accepted only in combination with a
 * real gateway URL/spawn so `pnpm bench:gateway` keeps working.
 */
export function isLiveGatewayConfigured(): boolean {
	return (
		Boolean(process.env["TRACELANE_EVAL_LIVE_GATEWAY_URL"]) ||
		process.env["TRACELANE_EVAL_SPAWN_GATEWAY"] === "1"
	);
}

/** Human-readable reason used in skip messages when no live gateway exists. */
export const LIVE_GATEWAY_SKIP_REASON =
	"requires a real gateway — set TRACELANE_EVAL_LIVE_GATEWAY_URL=<url> or " +
	"TRACELANE_EVAL_SPAWN_GATEWAY=1 (CI runs structural assertions only)";

// ── Live gateway utilities ─────────────────────────────────────────────────────

export interface MockGatewayOptions {
	providers?: string[];
	latencyMs?: number;
	errorRate?: number;
}

export interface MockGatewayContext {
	url: string;
	stop: () => void;
}

/**
 * Reaches a live gateway for perf eval runs. There is no in-process mock:
 * if no live gateway is configured (`isLiveGatewayConfigured()` is false),
 * this throws {@link LiveGatewayUnavailableError} so the caller skips rather
 * than measuring a fake `localhost:8080`.
 *
 * For real load tests, set `TRACELANE_EVAL_LIVE_GATEWAY_URL` (or
 * `TRACELANE_EVAL_SPAWN_GATEWAY=1`, with port via
 * `TRACELANE_EVAL_GATEWAY_PORT`, default 8080).
 *
 * @throws LiveGatewayUnavailableError when no live gateway is configured.
 */
export async function spawnGateway(
	_opts: MockGatewayOptions = {},
): Promise<MockGatewayContext> {
	if (!isLiveGatewayConfigured()) {
		throw new LiveGatewayUnavailableError(
			`spawnGateway ${LIVE_GATEWAY_SKIP_REASON}`,
		);
	}

	const externalUrl = process.env["TRACELANE_EVAL_LIVE_GATEWAY_URL"];
	const port = process.env["TRACELANE_EVAL_GATEWAY_PORT"] ?? "8080";
	const url = externalUrl ?? `http://127.0.0.1:${port}`;

	return {
		url,
		stop: () => {},
	};
}

export interface BenchResult {
	p50_latency_ms: number;
	p95_latency_ms: number;
	p99_latency_ms: number;
	error_rate: number;
	requests_completed: number;
	rps_sustained: number;
}

/**
 * Run a k6-style load test against a live gateway and return measured
 * percentiles.
 *
 * This function NEVER fabricates performance numbers. When no live gateway
 * is configured (`isLiveGatewayConfigured()` is false), it throws
 * {@link LiveGatewayUnavailableError}; the calling eval converts that into a
 * vitest skip. A perf gate that measures nothing must report "skipped", not
 * "passed".
 *
 * Runs a real `k6 run` subprocess (the scripts under `bench/gateway/`) with a
 * gateway reachable at `TRACELANE_EVAL_LIVE_GATEWAY_URL` (or spawned via
 * `TRACELANE_EVAL_SPAWN_GATEWAY=1`), parsing k6's `--summary-export` JSON for
 * the measured percentiles. A missing k6 binary (set `K6_BIN` to override) or a
 * missing summary throws — it never returns constants. k6's non-zero exit on a
 * threshold breach is tolerated (the summary is still consumed). An optional
 * `TRACELANE_EVAL_GATEWAY_TOKEN` is forwarded to the scripts as `AUTH_TOKEN`.
 *
 * @throws LiveGatewayUnavailableError when no live gateway is configured.
 */
export async function runK6(opts: {
	script: string;
	duration: string;
	target: string;
	vus?: number;
}): Promise<BenchResult> {
	if (!isLiveGatewayConfigured()) {
		throw new LiveGatewayUnavailableError(`runK6 ${LIVE_GATEWAY_SKIP_REASON}`);
	}

	// Real k6 subprocess. We NEVER fabricate: a missing k6 binary or a missing
	// summary file throws loudly so the bench fails rather than reporting fiction.
	const k6bin = process.env["K6_BIN"] ?? "k6";
	const dir = mkdtempSync(join(tmpdir(), "tlane-k6-"));
	const summaryPath = join(dir, "summary.json");
	const token = process.env["TRACELANE_EVAL_GATEWAY_TOKEN"];
	const args = [
		"run",
		"--duration",
		opts.duration,
		...(opts.vus ? ["--vus", String(opts.vus)] : []),
		"-e",
		`TARGET=${opts.target}`,
		"-e",
		`DURATION=${opts.duration}`,
		...(opts.vus ? ["-e", `VUS=${String(opts.vus)}`] : []),
		...(token ? ["-e", `AUTH_TOKEN=${token}`] : []),
		"--summary-export",
		summaryPath,
		opts.script,
	];

	try {
		const proc = spawnSync(k6bin, args, {
			encoding: "utf8",
			// 5 min ceiling covers the 60s sustained test plus k6 warmup/teardown.
			timeout: 300_000,
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (proc.error && (proc.error as NodeJS.ErrnoException).code === "ENOENT") {
			throw new Error(
				`runK6: k6 binary not found (tried "${k6bin}"). Install k6 ` +
					"(https://grafana.com/docs/k6/latest/set-up/install-k6/) or set K6_BIN. " +
					"This path measures real latency — it will not fabricate numbers.",
			);
		}

		// k6 exits non-zero when a threshold is breached (e.g. 99/107) but STILL
		// writes the summary. Only an absent summary is fatal — that means k6 never
		// produced metrics (config error, gateway unreachable, crash).
		let raw: string;
		try {
			raw = readFileSync(summaryPath, "utf8");
		} catch {
			throw new Error(
				`runK6: k6 produced no summary at ${summaryPath} (exit ${String(
					proc.status,
				)}). Gateway unreachable or k6 config error.\nstderr:\n${
					proc.stderr ?? ""
				}`,
			);
		}

		const summary = JSON.parse(raw) as K6Summary;
		const dur = summary.metrics?.["http_req_duration"]?.values;
		const reqs = summary.metrics?.["http_reqs"]?.values;
		const failed = summary.metrics?.["http_req_failed"]?.values;
		if (!dur || !reqs) {
			throw new Error(
				"runK6: k6 summary missing http_req_duration/http_reqs metrics — " +
					`cannot report latency. Raw head: ${raw.slice(0, 400)}`,
			);
		}

		return {
			p50_latency_ms: dur["med"] ?? dur["p(50)"] ?? Number.NaN,
			p95_latency_ms: dur["p(95)"] ?? Number.NaN,
			p99_latency_ms: dur["p(99)"] ?? Number.NaN,
			error_rate: failed?.["rate"] ?? 0,
			requests_completed: reqs["count"] ?? 0,
			rps_sustained: reqs["rate"] ?? 0,
		};
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}
