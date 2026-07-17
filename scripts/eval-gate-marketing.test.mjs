#!/usr/bin/env node
/**
 * Smoke test for scripts/eval-gate-marketing.mjs.
 *
 * Run from repo root:
 * node scripts/eval-gate-marketing.test.mjs
 *
 * Exits 0 on success, 1 on any divergence. Stand-alone — no test
 * framework, so it runs even on a fresh checkout without `pnpm install`.
 *
 * Cases covered:
 * - green claim → annotation stripped, surrounding text preserved
 * - red claim → replaced with disabled marker
 * - range "PP-PR1..PP-PR3" with one failing → whole range red
 * - missing report file → all claims red (fail-closed behaviour)
 */

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const SCRIPT = new URL("./eval-gate-marketing.mjs", import.meta.url).pathname;

function runCase(name, files, report, assertions) {
	const dir = mkdtempSync(join(tmpdir(), "eval-gate-smoke-"));
	try {
		for (const [path, content] of Object.entries(files)) {
			const full = join(dir, path);
			mkdirSync(full.substring(0, full.lastIndexOf("/")), { recursive: true });
			writeFileSync(full, content, "utf8");
		}
		if (report !== null) {
			writeFileSync(join(dir, "eval-report.json"), JSON.stringify(report), "utf8");
		}

		const args = ["--output", "dist", "--roots", "marketing"];
		if (report !== null) args.push("--report", "eval-report.json");
		else args.push("--report", "no-such-file.json");

		const r = spawnSync("node", [SCRIPT, ...args], { cwd: dir, encoding: "utf8" });
		if (r.status !== 0) {
			console.error(`[${name}] script exited ${r.status}: ${r.stderr}`);
			process.exit(1);
		}

		for (const [outPath, predicate] of Object.entries(assertions)) {
			const got = readFileSync(join(dir, "dist", outPath), "utf8");
			const ok = predicate(got);
			if (!ok) {
				console.error(`[${name}] assertion failed for ${outPath}\n--- output:\n${got}`);
				process.exit(1);
			}
		}

		console.log(`[${name}] OK`);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

// Case 1 — green claim retained.
runCase(
	"green claim retained",
	{ "marketing/a.md": "- Green claim <!-- eval:PP-G3 -->\n" },
	{ results: [{ id: "PP-G3", status: "pass" }] },
	{ "marketing/a.md": (s) => s.includes("Green claim") && !s.includes("<!--") && !s.includes("disabled") },
);

// Case 2 — red claim replaced.
runCase(
	"red claim replaced",
	{ "marketing/b.md": "- Red claim <!-- eval:PP-FAKE -->\n" },
	{ results: [] },
	{ "marketing/b.md": (s) => s.includes("currently disabled") },
);

// Case 3 — range with one failing → whole range red.
runCase(
	"range with one failing → red",
	{ "marketing/c.md": "- Claim <!-- eval:PP-PR1..PP-PR3 -->\n" },
	{
		results: [
			{ id: "PP-PR1", status: "pass" },
			{ id: "PP-PR2", status: "pass" },
			{ id: "PP-PR3", status: "fail" },
		],
	},
	{ "marketing/c.md": (s) => s.includes("currently disabled") },
);

// Case 4 — missing report → fail-closed (treat as red).
runCase(
	"missing report → fail-closed",
	{ "marketing/d.md": "- Claim <!-- eval:PP-G3 -->\n" },
	null,
	{ "marketing/d.md": (s) => s.includes("currently disabled") },
);

console.log("all eval-gate smoke tests passed");
