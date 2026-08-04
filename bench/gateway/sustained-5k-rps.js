import { check } from "k6";
// PP-G3 — sustained gateway throughput (k6 load test).
//
// Drives a CONSTANT arrival rate (open model) against the gateway to prove it
// sustains the target RPS without latency collapse — the Rust/tokio claim vs a
// Python-GIL competitor. Uses constant-arrival-rate (not fixed VUs) so the rate
// is the independent variable and queueing shows up as rising latency, not as
// throttled load.
//
// This script NEVER hardcodes a result — k6 reports the measured throughput,
// error rate, and percentiles. The harness parses k6's --summary-export JSON.
//
// Env (all optional; the eval harness injects TARGET/DURATION):
//   TARGET      gateway base URL          (default http://127.0.0.1:8080)
//   ENDPOINT    path to exercise          (default /v1/chat/completions)
//   MODEL       reserved bench model id   (default __bench_mock_fast)
//   AUTH_TOKEN  bearer token              (default none)
//   RATE        target requests/sec       (default 5000)
//   DURATION    sustained duration        (default 60s)
//   VUS         pre-allocated VUs         (default 200)
//   MAX_VUS     ceiling VUs               (default 2000)
import http from "k6/http";
import { summaryGate } from "./summary-gate.mjs";

const TARGET = __ENV.TARGET || "http://127.0.0.1:8080";
const ENDPOINT = __ENV.ENDPOINT || "/v1/chat/completions";
const AUTH = __ENV.AUTH_TOKEN || "";
const PAYLOAD =
	__ENV.PAYLOAD ||
	JSON.stringify({
		model: __ENV.MODEL || "__bench_mock_fast",
		messages: [{ role: "user", content: "ping" }],
		max_tokens: 1,
	});

export const options = {
	scenarios: {
		sustained: {
			executor: "constant-arrival-rate",
			rate: Number(__ENV.RATE || 5000),
			timeUnit: "1s",
			duration: __ENV.DURATION || "60s",
			preAllocatedVUs: Number(__ENV.VUS || 200),
			maxVUs: Number(__ENV.MAX_VUS || 2000),
		},
	},
	summaryTrendStats: ["avg", "min", "med", "p(90)", "p(95)", "p(99)", "max"],
	thresholds: {
		http_req_duration: ["p(99)<25"],
		http_req_failed: [{ threshold: "rate<0.001", abortOnFail: true }],
	},
};

export default function () {
	const res = http.post(`${TARGET}${ENDPOINT}`, PAYLOAD, {
		headers: {
			"Content-Type": "application/json",
			...(AUTH ? { Authorization: `Bearer ${AUTH}` } : {}),
		},
	});
	check(res, { "status is 2xx": (r) => r.status >= 200 && r.status < 300 });
}

// Same unconditional 2xx gate as overhead-measurement.js. This script shipped
// with NO gate, which is why its p99 result came back with an unvalidated
// success rate and had to be logged as a question rather than a number.
export function handleSummary(data) {
	return summaryGate(data, __ENV.SUMMARY_EXPORT);
}
