// Falsification suite for the benchmark 2xx gate.
//
//   node bench/gateway/summary-gate.selftest.mjs
//
// THE POINT OF THE PASS HALF. The first version of this gate was only ever
// tested for BLOCKING a bad run. It shipped unable to pass ANY run — it read
// `metrics.http_reqs.count` instead of `metrics.http_reqs.values.count`, so
// every real summary looked like "no data" — and it additionally threw a
// ReferenceError on its own success branch (`passes` was never defined; the
// variable was `cPass`). Two independent defects, both on the success path,
// both invisible to a block-only test. Every case below that asserts PASS
// exists because of that.
//
// Fixtures in testdata/ are REAL k6 payloads captured from live runs on
// v0.55.0 and v2.0.0 (25% of requests deliberately 429). They are not
// hand-written: a hand-written fixture would encode the same wrong assumption
// the gate had, and pass vacuously.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	MAX_NON_2XX_RATE,
	evaluateSummary,
	renderVerdict,
	summaryGate,
} from "./summary-gate.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const load = (n) => JSON.parse(readFileSync(join(HERE, "testdata", n), "utf8"));
const versions = [
	...new Set(
		readdirSync(join(HERE, "testdata"))
			.filter((f) => f.endsWith(".json"))
			.map((f) => f.replace(/^k6-/, "").replace(/-(good|bad)\.json$/, "")),
	),
].sort();

let fails = 0;
const t = (name, fn) => {
	try {
		fn();
		console.log(`  [PASS] ${name}`);
	} catch (e) {
		console.log(`  [FAIL] ${name} — ${e.message}`);
		fails++;
	}
};
const eq = (a, b, m) => {
	if (a !== b) throw new Error(`${m}: expected ${b}, got ${a}`);
};
const ok = (c, m) => {
	if (!c) throw new Error(m);
};

console.log(`k6 payload versions under test: ${versions.join(", ")}\n`);
ok(versions.length >= 2, "need >=2 captured k6 versions");

// --- HALF ONE: the gate must PASS a real, valid run -------------------------
for (const v of versions) {
	t(`${v}: good run is VALID`, () => {
		const r = evaluateSummary(load(`k6-${v}-good.json`));
		ok(r.valid, `good run rejected: ${r.reason}`);
		ok(r.total > 100, `total too low to be a real run: ${r.total}`);
		eq(r.twoXx, r.total, "every request should be 2xx");
		eq(r.nonTwoXxRate, 0, "non-2xx rate");
		eq(r.source, "http_req_failed", "signal source");
		ok(typeof r.p99 === "number" && r.p99 > 0, `p99 not read: ${r.p99}`);
	});
	t(`${v}: good run RENDERS without throwing`, () => {
		// The original success branch threw ReferenceError here.
		const s = renderVerdict(evaluateSummary(load(`k6-${v}-good.json`)));
		ok(s.includes("measurement valid"), "missing valid marker");
		ok(!s.includes("undefined"), `rendered 'undefined': ${s.trim()}`);
	});
	t(`${v}: good run WRITES the export`, () => {
		const out = summaryGate(load(`k6-${v}-good.json`), "/tmp/x.json");
		ok("/tmp/x.json" in out, "valid run must write its export");
	});
}

// --- HALF TWO: the gate must BLOCK ------------------------------------------
for (const v of versions) {
	t(`${v}: 25%-rejected run is INVALID`, () => {
		const r = evaluateSummary(load(`k6-${v}-bad.json`));
		ok(!r.valid, "bad run accepted");
		eq(r.reason, "non-2xx-over-ceiling", "reason");
		ok(r.nonTwoXxRate > 0.2, `expected ~0.25, got ${r.nonTwoXxRate}`);
	});
	t(`${v}: rejected run WITHHOLDS the export`, () => {
		const out = summaryGate(load(`k6-${v}-bad.json`), "/tmp/x.json");
		ok(!("/tmp/x.json" in out), "invalid run must not write an export");
		ok(out.stdout.includes("ABORTED"), "missing abort marker");
	});
}

// --- Regression guard: the exact bug this replaced --------------------------
t("SHALLOW shape (the original bug) is INVALID, not silently accepted", () => {
	// What the old gate believed the payload looked like.
	const r = evaluateSummary({
		metrics: {
			http_reqs: { count: 5000 },
			http_req_failed: { value: 0 },
			checks: { passes: 5000, fails: 0 },
		},
	});
	ok(!r.valid, "a shape with no .values must never read as a valid run");
	eq(r.reason, "no-usable-signal", "reason");
});

// --- Polarity: checks fallback must invert, http_req_failed must not --------
for (const v of versions) {
	t(`${v}: checks-only fallback keeps polarity (good stays good)`, () => {
		const d = load(`k6-${v}-good.json`);
		delete d.metrics.http_req_failed;
		const r = evaluateSummary(d);
		eq(r.source, "checks", "should fall back to checks");
		ok(r.valid, "100%-passing checks must read as valid");
		eq(r.nonTwoXxRate, 0, "checks rate 1.0 must invert to 0 non-2xx");
	});
	t(`${v}: checks-only fallback keeps polarity (bad stays bad)`, () => {
		const d = load(`k6-${v}-bad.json`);
		delete d.metrics.http_req_failed;
		const r = evaluateSummary(d);
		eq(r.source, "checks", "should fall back to checks");
		ok(!r.valid, "75%-passing checks must read as INVALID, not 75%-good");
		ok(r.nonTwoXxRate > 0.2, `expected ~0.25 non-2xx, got ${r.nonTwoXxRate}`);
	});
}

// --- No-data cases: all fail closed ----------------------------------------
for (const [name, payload] of [
	["empty object", {}],
	["no metrics key", { root_group: {} }],
	["metrics present but empty", { metrics: {} }],
	[
		"zero requests recorded",
		{
			metrics: {
				http_reqs: { values: { count: 0, rate: 0 } },
				http_req_failed: { values: { rate: 0, passes: 0, fails: 0 } },
			},
		},
	],
	["null", null],
]) {
	t(`no-data: ${name} is INVALID`, () => {
		const r = evaluateSummary(payload);
		ok(!r.valid, "must refuse");
		eq(r.reason, "no-usable-signal", "reason");
		ok(!renderVerdict(r).includes("undefined"), "rendered 'undefined'");
	});
}

// --- The ceiling actually binds --------------------------------------------
t("ceiling binds just above and passes just below", () => {
	const mk = (rate) => ({
		metrics: {
			http_reqs: { values: { count: 100000 } },
			http_req_failed: { values: { rate } },
		},
	});
	ok(evaluateSummary(mk(MAX_NON_2XX_RATE)).valid, "at ceiling should pass");
	ok(
		!evaluateSummary(mk(MAX_NON_2XX_RATE * 1.001)).valid,
		"just over ceiling must fail",
	);
});

console.log(
	fails === 0
		? `\nSelftest passed — both halves (gate PASSES valid runs, BLOCKS invalid ones).`
		: `\nSELFTEST FAILED — ${fails} case(s).`,
);
process.exit(fails === 0 ? 0 : 1);
