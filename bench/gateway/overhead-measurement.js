// PP-G7 — gateway request-processing overhead (k6 load test).
//
// Measures end-to-end gateway latency under moderate concurrency. To read the
// result as *gateway overhead* (CLAUDE.md budget: p99 <25ms; PP-G7 target
// <10ms), the gateway MUST be configured to route to an INSTANT mock upstream
// so provider time ≈ 0 and http_req_duration ≈ the gateway's own processing.
// See bench/gateway/README.md for the node setup.
//
// This script NEVER hardcodes a result — k6 reports the measured percentiles.
// The harness (evals/src/harness.ts::runK6) parses k6's --summary-export JSON.
//
// Env (all optional; the eval harness injects TARGET/DURATION/VUS):
//   TARGET      gateway base URL                (default http://127.0.0.1:8080)
//   ENDPOINT    path to exercise                (default /v1/chat/completions)
//   MODEL       reserved bench model id          (default __bench_mock_instant)
//   AUTH_TOKEN  bearer token (tlane_… / BYOK)   (default none)
//   VUS         virtual users                   (default 50)
//   DURATION    test duration                   (default 30s)
import http from "k6/http";
import { check } from "k6";

const TARGET = __ENV.TARGET || "http://127.0.0.1:8080";
const ENDPOINT = __ENV.ENDPOINT || "/v1/chat/completions";
const AUTH = __ENV.AUTH_TOKEN || "";
const PAYLOAD =
	__ENV.PAYLOAD ||
	JSON.stringify({
		model: __ENV.MODEL || "__bench_mock_instant",
		messages: [{ role: "user", content: "ping" }],
		max_tokens: 1,
	});

export const options = {
	vus: Number(__ENV.VUS || 50),
	duration: __ENV.DURATION || "30s",
	// Thresholds are informational for standalone runs (k6 still exports the
	// summary on breach). The CLAUDE.md hard budget for gateway overhead is
	// p99 <25ms; PP-G7's eval asserts the tighter <10ms target separately.
	thresholds: {
		http_req_duration: ["p(99)<25"],
		http_req_failed: ["rate<0.001"],
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
