// UNCONDITIONAL 2xx GATE for k6 benchmark runs (B-187b).
//
// Pure decision function, deliberately in its own module with NO k6 imports, so
// it can be exercised by plain `node` against REAL captured k6 payloads
// (`testdata/`). The previous version lived inline in the k6 script and was
// therefore only ever executed by a live benchmark — which is how it shipped
// unable to pass ANY run.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS
//
// Two runs of this harness produced clean-looking latency from requests that
// were almost entirely REJECTED:
//   - the reserved bench model 400'd `unroutable_model`, and
//   - the self-host tenant fell to Free = 60 rpm while k6 drove 27,075/s, so
//     812,220 of 812,273 requests were 429'd.
// Both times `http_req_duration` looked publishable — p50 1.489ms, p95 4.207ms.
// This is not a rate-limit check or an auth check; it is a check that the thing
// we measured was a SUCCESSFUL request, whatever the next failure mode is.
//
// ---------------------------------------------------------------------------
// THE SHAPE — read this before touching any metric access below.
//
// Every k6 metric nests its numbers under `.values`. Verified identical on k6
// v0.55.0, v1.0.0 and v2.0.0 (see testdata/, captured from real runs):
//
//   metrics["http_reqs"]       = { type:"counter", values:{ count, rate } }
//   metrics["http_req_failed"] = { type:"rate",    values:{ rate, passes, fails } }
//   metrics["checks"]          = { type:"rate",    values:{ rate, passes, fails } }
//
// The first version of this gate read `metrics.http_reqs.count`,
// `metrics.http_req_failed.value` and `checks.passes` — one level too shallow,
// so all three were `undefined` on EVERY k6 version. That collapsed to
// "no usable success metric" and the gate refused every run, including valid
// ones. A gate that cannot pass is a wall, not a gate: that false-positive is
// as harmful as the false-negative it exists to prevent.
//
// POLARITY TRAP — these two look alike and point OPPOSITE ways:
//   http_req_failed.values.rate  is a FAILURE fraction (0.2486 on a 25%-bad run)
//   checks.values.rate           is a SUCCESS fraction (0.7514 on the same run)
// Mixing them silently inverts the verdict, so each is converted at its own
// read site below and the source is reported in the result.
// ---------------------------------------------------------------------------

/** Ceiling for non-2xx responses before a run is declared invalid. */
export const MAX_NON_2XX_RATE = 0.001; // 0.1%

/**
 * Decide whether a k6 summary describes a VALID measurement.
 *
 * Fail-CLOSED: any shape this cannot positively read is invalid. A summary that
 * does not prove success is not a summary that proves success.
 *
 * @param {object} data  k6 `handleSummary` payload (or parsed --summary-export)
 * @param {number} [maxNonTwoXx]
 * @returns {{valid:boolean, reason:string, total:number, twoXx:number,
 *            nonTwoXxRate:(number|null), source:(string|null), p99:(number|null)}}
 */
export function evaluateSummary(data, maxNonTwoXx = MAX_NON_2XX_RATE) {
	const metrics = (data && data.metrics) || {};
	// Single accessor: every read goes through `.values` exactly once, so the
	// shallow-read bug cannot be reintroduced one metric at a time.
	const valuesOf = (name) => {
		const m = metrics[name];
		return m && typeof m === "object" && m.values && typeof m.values === "object"
			? m.values
			: null;
	};
	const num = (o, k) => (o && typeof o[k] === "number" ? o[k] : null);

	const reqs = valuesOf("http_reqs");
	const total = num(reqs, "count") ?? 0;

	const failed = valuesOf("http_req_failed");
	const checks = valuesOf("checks");
	const durVals = valuesOf("http_req_duration");
	const p99 = num(durVals, "p(99)");

	// Prefer http_req_failed (a FAILURE fraction, used as-is); fall back to
	// checks (a SUCCESS fraction, inverted here at its own read site).
	let nonTwoXxRate = null;
	let source = null;
	const failRate = num(failed, "rate");
	const checkRate = num(checks, "rate");
	if (failRate !== null) {
		nonTwoXxRate = failRate;
		source = "http_req_failed";
	} else if (checkRate !== null) {
		nonTwoXxRate = 1 - checkRate;
		source = "checks";
	}

	if (total === 0 || nonTwoXxRate === null) {
		return {
			valid: false,
			reason: "no-usable-signal",
			total,
			twoXx: 0,
			nonTwoXxRate,
			source,
			p99,
		};
	}
	const twoXx = total - Math.round(nonTwoXxRate * total);
	if (nonTwoXxRate > maxNonTwoXx) {
		return {
			valid: false,
			reason: "non-2xx-over-ceiling",
			total,
			twoXx,
			nonTwoXxRate,
			source,
			p99,
		};
	}
	return { valid: true, reason: "ok", total, twoXx, nonTwoXxRate, source, p99 };
}

/**
 * Render the operator-facing block for a verdict. Kept next to the decision so
 * the failure text cannot drift away from the condition that produced it.
 */
export function renderVerdict(v, maxNonTwoXx = MAX_NON_2XX_RATE) {
	if (v.valid) {
		return (
			`\n  ✓ ${v.twoXx}/${v.total} requests 2xx ` +
			`(non-2xx ${(v.nonTwoXxRate * 100).toFixed(4)}%, via ${v.source}) — measurement valid\n`
		);
	}
	// Distinguish "no data" from "bad data": `abortOnFail` can kill a run before
	// any sample is recorded, and reporting that as "100% of 0" is itself a
	// fabricated statistic.
	const detail =
		v.reason === "no-usable-signal"
			? `NO requests completed, or the summary carried no readable success metric.\n` +
				`    Read metrics as metrics[name].values.{count,rate} — NOT metrics[name].count.`
			: `non-2xx rate : ${(v.nonTwoXxRate * 100).toFixed(4)}%  ` +
				`(${v.total - v.twoXx} of ${v.total}, via ${v.source}); ceiling is ${maxNonTwoXx * 100}%`;
	return (
		`\n\n  ✗ BENCHMARK ABORTED — the measurement is INVALID.\n\n` +
		`    ${detail}\n` +
		`    Latency percentiles from rejected requests are meaningless. NO summary\n` +
		`    export was written, deliberately — a file on disk becomes a published\n` +
		`    number. Diagnose the status code first:\n\n` +
		`      401 -> auth (AUTH_TOKEN wrong/unset)\n` +
		`      400 -> unroutable model (is TRACELANE_BENCH_MOCK_UPSTREAM set?)\n` +
		`      429 -> rate limit (bench tier needs NO Postgres control plane)\n\n` +
		`    Confirm a single request returns 200 by hand before re-running.\n\n`
	);
}

/**
 * Shared `handleSummary` body. Writes the export ONLY on a valid measurement —
 * withholding the file is the enforcement, since a summary on disk is what
 * turns a bad run into a published number.
 */
export function summaryGate(data, summaryExportPath) {
	const v = evaluateSummary(data);
	const out = { stdout: renderVerdict(v) };
	if (v.valid && summaryExportPath) {
		out[summaryExportPath] = JSON.stringify(data, null, 2);
	}
	return out;
}
