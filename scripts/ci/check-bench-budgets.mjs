#!/usr/bin/env node
/**
 * Performance-budget gate (punchlist #5).
 *
 * The `bench:` CI job used to RUN the criterion benches and throw their
 * measurements away — so a hot-path regression could not fail the build. This
 * script closes that gap: it reads the criterion `estimates.json` each bench
 * already writes and fails CI when a measured time exceeds its declared budget.
 *
 * It enforces real numbers only. If a bench's `estimates.json` is missing it
 * fails loudly ("bench not run") rather than silently passing — the old
 * fabricated-pass failure mode the V1 audit flagged.
 *
 * Budgets live in `scripts/ci/bench-budgets.json` (data, not code). Each entry:
 * { id, path, budgetNs, target }
 * where `path` is relative to the repo's `target/criterion` directory and
 * `budgetNs` is a CI-load-tolerant ceiling above the documented hot-path target
 * (generous enough to absorb runner jitter, tight enough to catch a real
 * regression — typically a 10x blowup).
 *
 * Usage:
 * node scripts/ci/check-bench-budgets.mjs # enforce; missing = fail
 * node scripts/ci/check-bench-budgets.mjs --allow-missing # skip absent benches
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const CRITERION_ROOT = join(REPO_ROOT, "target", "criterion");

const allowMissing = process.argv.includes("--allow-missing");

/** @type {{id:string,path:string,budgetNs:number,target:string}[]} */
const budgets = JSON.parse(
	readFileSync(join(HERE, "bench-budgets.json"), "utf8"),
).benches;

/** Read the criterion mean point-estimate (nanoseconds) for one bench. */
function readMeanNs(relPath) {
	const file = join(CRITERION_ROOT, relPath, "new", "estimates.json");
	const json = JSON.parse(readFileSync(file, "utf8"));
	// criterion stores point estimates in nanoseconds.
	const mean = json?.mean?.point_estimate;
	if (typeof mean !== "number") {
		throw new Error(`no mean.point_estimate in ${file}`);
	}
	return mean;
}

const failures = [];
const rows = [];

for (const b of budgets) {
	let measured;
	try {
		measured = readMeanNs(b.path);
	} catch (err) {
		const msg = `${b.id}: estimates.json missing or malformed (${b.path}) — bench not run?`;
		if (allowMissing) {
			rows.push({ id: b.id, measured: "—", budget: b.budgetNs, ok: "skip" });
			continue;
		}
		failures.push(msg);
		rows.push({ id: b.id, measured: "MISSING", budget: b.budgetNs, ok: "FAIL" });
		continue;
	}
	const ok = measured <= b.budgetNs;
	if (!ok) {
		failures.push(
			`${b.id}: ${measured.toFixed(0)}ns exceeds budget ${b.budgetNs}ns (target: ${b.target})`,
		);
	}
	rows.push({
		id: b.id,
		measured: `${measured.toFixed(0)}ns`,
		budget: `${b.budgetNs}ns`,
		ok: ok ? "ok" : "FAIL",
	});
}

console.log("Performance budget gate (criterion mean vs ceiling):\n");
for (const r of rows) {
	console.log(
		` [${String(r.ok).padEnd(4)}] ${r.id.padEnd(38)} ${String(r.measured).padStart(12)} <= ${r.budget}`,
	);
}

if (failures.length > 0) {
	console.error(`\n${failures.length} budget failure(s):`);
	for (const f of failures) console.error(` - ${f}`);
	console.error(
		"\nRun the benches first (pnpm bench:gateway && pnpm bench:ingest), then re-run this gate.",
	);
	process.exit(1);
}

console.log(`\nAll ${rows.length} benches within budget.`);
