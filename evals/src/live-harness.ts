/**
 * Live-gateway harness — sibling of harness.ts.
 *
 * `harness.ts`'s `spawnGateway` is intentionally a mock so the bulk of
 * the eval suite runs in CI without a working Rust toolchain. This file
 * adds the live counterpart, used when the operator opts in via env.
 *
 * Activation rules:
 *   - `TRACELANE_EVAL_LIVE_GATEWAY_URL` set → use that URL, skip if 5xx.
 *   - else if `TRACELANE_EVAL_SPAWN_GATEWAY=1` and `cargo` is on PATH →
 *     spawn `cargo run --release -p gateway` as a subprocess and tear
 *     it down on stop().
 *   - else → mark the test skipped via `live.skip = true`.
 *
 * Tests should branch on `live.skip` and call `it.skip(...)` accordingly.
 *
 * Why a separate file: keeps harness.ts pure for the CI codepath, and
 * lets the live path evolve (subprocess management, port discovery,
 * health-probe semantics) without churning the mock.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const HEALTH_TIMEOUT_MS = 60_000;
const HEALTH_PROBE_INTERVAL_MS = 250;

export interface LiveGatewayContext {
	/** Gateway URL — only safe to use when `skip === false`. */
	url: string;
	/** When true, the eval should call `it.skip(...)` instead of running. */
	skip: boolean;
	/** Reason for the skip — surfaced into test reports. */
	skipReason?: string;
	/** Tear down the gateway. No-op for URL-mode; kills the subprocess for spawn-mode. */
	stop: () => Promise<void>;
}

export interface SpawnLiveGatewayOptions {
	/**
	 * Optional health-probe URL suffix. Default: `/healthz`.
	 * The harness considers the gateway ready when this returns 2xx.
	 */
	healthPath?: string;
	/**
	 * Override the default subprocess command. Useful for self-host
	 * setups where the binary lives in a non-standard location.
	 */
	command?: { cmd: string; args: string[] };
}

/** Probe an HTTP URL until it returns 2xx or `timeoutMs` elapses. */
async function waitForReady(url: string, timeoutMs: number): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			const r = await fetch(url, { signal: AbortSignal.timeout(2_000) });
			if (r.ok) return true;
		} catch {
			// not ready yet — fall through to retry
		}
		await sleep(HEALTH_PROBE_INTERVAL_MS);
	}
	return false;
}

/**
 * Spawn (or reach) a live gateway. Use in `beforeAll` of a describe block
 * and check `ctx.skip` before each `it`.
 */
export async function spawnLiveGateway(
	opts: SpawnLiveGatewayOptions = {},
): Promise<LiveGatewayContext> {
	const healthPath = opts.healthPath ?? "/healthz";

	// Mode 1 — pre-existing live gateway.
	const externalUrl = process.env["TRACELANE_EVAL_LIVE_GATEWAY_URL"];
	if (externalUrl) {
		const ok = await waitForReady(`${externalUrl}${healthPath}`, 5_000);
		if (!ok) {
			return {
				url: externalUrl,
				skip: true,
				skipReason: `Gateway at ${externalUrl}${healthPath} not healthy within 5s`,
				stop: async () => {},
			};
		}
		return { url: externalUrl, skip: false, stop: async () => {} };
	}

	// Mode 2 — spawn cargo subprocess.
	if (process.env["TRACELANE_EVAL_SPAWN_GATEWAY"] === "1") {
		const cmd = opts.command?.cmd ?? "cargo";
		const args = opts.command?.args ?? ["run", "--release", "-p", "gateway"];
		const port = process.env["TRACELANE_EVAL_GATEWAY_PORT"] ?? "8080";
		const url = `http://127.0.0.1:${port}`;

		let child: ChildProcess;
		try {
			child = spawn(cmd, args, {
				stdio: ["ignore", "pipe", "pipe"],
				env: { ...process.env, TRACELANE_GATEWAY_PORT: port },
			});
		} catch (err) {
			return {
				url,
				skip: true,
				skipReason: `failed to spawn ${cmd}: ${err instanceof Error ? err.message : String(err)}`,
				stop: async () => {},
			};
		}

		const ok = await waitForReady(`${url}${healthPath}`, HEALTH_TIMEOUT_MS);
		if (!ok) {
			child.kill("SIGTERM");
			return {
				url,
				skip: true,
				skipReason: `Gateway did not become ready on ${url}${healthPath} within ${HEALTH_TIMEOUT_MS}ms`,
				stop: async () => {},
			};
		}

		return {
			url,
			skip: false,
			stop: async () => {
				child.kill("SIGTERM");
				await sleep(500);
				if (!child.killed) child.kill("SIGKILL");
			},
		};
	}

	// Mode 3 — neither: tests skip.
	return {
		url: "",
		skip: true,
		skipReason:
			"Set TRACELANE_EVAL_LIVE_GATEWAY_URL=<url> or TRACELANE_EVAL_SPAWN_GATEWAY=1 to enable live evals",
		stop: async () => {},
	};
}

// ── Predictive-layer assertion helpers ──────────────────────────────────────

export interface PredictiveDecision {
	rule_id: string;
	severity: "block" | "warn" | "allow";
	score?: number;
	[key: string]: unknown;
}

/**
 * Pull predictive decisions from a gateway response. Tracelane emits them in:
 *   1. The `x-tracelane-predictive` header (comma-separated rule_ids), AND
 *   2. JSON body `tracelane_predictive` array on `/v1/predictive/inspect`.
 *
 * Returns `[]` when the response carries no predictive output (allow).
 */
export async function readPredictiveDecisions(
	response: Response,
): Promise<PredictiveDecision[]> {
	const header = response.headers.get("x-tracelane-predictive");
	const headerIds = header ? header.split(",").map((s) => s.trim()).filter(Boolean) : [];

	let bodyDecisions: PredictiveDecision[] = [];
	try {
		const body = await response.clone().json();
		if (body && Array.isArray((body as Record<string, unknown>).tracelane_predictive)) {
			bodyDecisions = (body as { tracelane_predictive: PredictiveDecision[] }).tracelane_predictive;
		}
	} catch {
		// non-JSON response — fall back to header only
	}

	if (bodyDecisions.length > 0) return bodyDecisions;
	return headerIds.map((rule_id) => ({ rule_id, severity: "warn" }));
}

/**
 * Assert that a predictive decision with the given `rule_id` fired.
 * Throws with a descriptive message if not present.
 */
export function expectPredictiveFired(
	decisions: PredictiveDecision[],
	ruleId: string,
	severity?: "block" | "warn",
): PredictiveDecision {
	const hit = decisions.find((d) => d.rule_id === ruleId);
	if (!hit) {
		const seen = decisions.map((d) => d.rule_id).join(", ") || "<none>";
		throw new Error(
			`Expected predictive rule '${ruleId}' to fire, but did not. Saw: [${seen}]`,
		);
	}
	if (severity && hit.severity !== severity) {
		throw new Error(
			`Expected '${ruleId}' to fire with severity '${severity}', but got '${hit.severity}'`,
		);
	}
	return hit;
}
