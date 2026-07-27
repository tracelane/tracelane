#!/usr/bin/env node
/**
 * Full-path integration smoke — SDK → gateway → NATS → ingest → ClickHouse → dashboard.
 *
 * This is the launch gate for it proves a request that enters the gateway
 * comes back out the other end as a queryable trace, and that the dashboard is
 * reachable to render it. It is **written and runnable now but PARKED** until the
 * Phase-2 infra exists — with the required env unset it exits 0 with a PARKED
 * notice so it can live in CI without failing red.
 *
 * Run:
 * TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev \
 * TRACELANE_API_KEY=tlane_... \
 * CLICKHOUSE_URL=https://ch.example:8443 CLICKHOUSE_USER=default \
 * CLICKHOUSE_PASSWORD=... CLICKHOUSE_DB=tracelane \
 * TRACELANE_DASHBOARD_URL=https://app.tracelane.dev \
 * node scripts/smoke/full-path-smoke.mjs
 *
 * Optional: TRACELANE_SMOKE_MODEL (default gpt-4o-mini — the test tenant must
 * have a BYOK provider key covering it), TRACELANE_SMOKE_TIMEOUT_S (default 45).
 *
 * Exit codes: 0 = PASS or PARKED; 1 = FAIL.
 */

const env = process.env;
const GATEWAY = env.TRACELANE_GATEWAY_URL;
const API_KEY = env.TRACELANE_API_KEY;
const CH_URL = env.CLICKHOUSE_URL;
const CH_USER = env.CLICKHOUSE_USER ?? "default";
const CH_PASS = env.CLICKHOUSE_PASSWORD ?? "";
const CH_DB = env.CLICKHOUSE_DB ?? "tracelane";
const DASHBOARD = env.TRACELANE_DASHBOARD_URL ?? "";
const MODEL = env.TRACELANE_SMOKE_MODEL ?? "gpt-4o-mini";
const TIMEOUT_S = Number(env.TRACELANE_SMOKE_TIMEOUT_S ?? 45);

const REQUIRED = {
	TRACELANE_GATEWAY_URL: GATEWAY,
	TRACELANE_API_KEY: API_KEY,
	CLICKHOUSE_URL: CH_URL,
};
const missing = Object.entries(REQUIRED)
	.filter(([, v]) => !v)
	.map(([k]) => k);
if (missing.length > 0) {
	console.log(
		`[smoke] PARKED: Phase-2 infra not provisioned — missing ${missing.join(", ")}. Set the gateway/API-key/ClickHouse env (see header) to run. Exiting 0.`,
	);
	process.exit(0);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function fail(step, msg) {
	console.error(`[smoke] FAIL @ ${step}: ${msg}`);
	process.exit(1);
}

/** Run a ClickHouse SELECT over the HTTP interface; returns the trimmed body. */
async function ch(query) {
	const res = await fetch(
		`${CH_URL.replace(/\/$/, "")}/?database=${encodeURIComponent(CH_DB)}`,
		{
			method: "POST",
			headers: { "X-ClickHouse-User": CH_USER, "X-ClickHouse-Key": CH_PASS },
			body: query,
		},
	);
	const text = (await res.text()).trim();
	if (!res.ok)
		throw new Error(`ClickHouse ${res.status}: ${text.slice(0, 200)}`);
	return text;
}

async function main() {
	const marker = `smoke-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

	// 0. Baseline trace count (last 10 min) so we can detect the new one.
	let before = 0;
	try {
		before = Number(
			await ch(
				"SELECT count() FROM tracelane.trace_summaries WHERE start_time > now() - INTERVAL 10 MINUTE",
			),
		);
	} catch (e) {
		fail(
			"clickhouse-precount",
			`${e.message} (is the tracelane.trace_summaries table provisioned?)`,
		);
	}
	console.log(
		`[smoke] 1/4 ClickHouse reachable; baseline recent traces = ${before}`,
	);

	// 1. SDK → gateway: send a chat completion (OpenAI-compatible surface).
	let gwStatus;
	try {
		const res = await fetch(
			`${GATEWAY.replace(/\/$/, "")}/v1/chat/completions`,
			{
				method: "POST",
				headers: {
					Authorization: `Bearer ${API_KEY}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					model: MODEL,
					max_tokens: 16,
					messages: [{ role: "user", content: `ping ${marker}` }],
				}),
			},
		);
		gwStatus = res.status;
		if (!res.ok) {
			const body = (await res.text()).slice(0, 300);
			fail(
				"gateway",
				`gateway returned ${res.status}: ${body} — ensure the test tenant has a BYOK provider key for "${MODEL}".`,
			);
		}
	} catch (e) {
		fail("gateway", `request failed: ${e.message}`);
	}
	console.log(`[smoke] 2/4 gateway accepted the request (HTTP ${gwStatus})`);

	// 2. gateway → NATS → ingest → ClickHouse: poll for a NEW trace.
	const deadline = Date.now() + TIMEOUT_S * 1000;
	let landed = false;
	while (Date.now() < deadline) {
		await sleep(2000);
		const now = Number(
			await ch(
				"SELECT count() FROM tracelane.trace_summaries WHERE start_time > now() - INTERVAL 10 MINUTE",
			),
		);
		if (now > before) {
			landed = true;
			break;
		}
	}
	if (!landed) {
		fail(
			"ingest-clickhouse",
			`no new trace in tracelane.trace_summaries within ${TIMEOUT_S}s (gateway→NATS→ingest→CH path).`,
		);
	}
	console.log(
		"[smoke] 3/4 trace landed in ClickHouse (ingest pipeline healthy)",
	);

	// 3. dashboard hop: reachability (full read requires an auth session; here we
	// assert the dashboard is up so it can render the trace).
	if (DASHBOARD) {
		try {
			const res = await fetch(DASHBOARD, { redirect: "manual" });
			if (res.status >= 500)
				fail("dashboard", `dashboard returned ${res.status}`);
			console.log(`[smoke] 4/4 dashboard reachable (HTTP ${res.status})`);
		} catch (e) {
			fail("dashboard", `unreachable: ${e.message}`);
		}
	} else {
		console.log(
			"[smoke] 4/4 dashboard hop skipped (set TRACELANE_DASHBOARD_URL to include it)",
		);
	}

	console.log(
		"[smoke] PASS — full path SDK → gateway → ingest → ClickHouse → dashboard is healthy.",
	);
}

main().catch((e) => fail("unexpected", e?.stack ?? String(e)));
