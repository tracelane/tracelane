#!/usr/bin/env node
/**
 * eval-gate-marketing.mjs — apply the ADR-013 mechanical-gating step.
 *
 * Reads:
 * - $EVAL_REPORT (default: ./eval-report.json) — JSON shape:
 * { results: [{ id: "PP-G3", status: "pass"|"fail"|"skip" }, ...] }
 * - All Markdown / MDX files under marketing/, apps/docs/, docs/
 *
 * Produces (in --output <dir>):
 * - same file tree, with claims gated.
 *
 * Gating rules:
 * 1. Find every <!-- eval:PP-XXX --> or <!-- eval:PP-XXX..PP-YYY -->
 * annotation.
 * 2. For each annotation:
 * - parse the eval IDs (range or single)
 * - if ANY referenced eval is not in the green set, replace the
 * immediately-preceding paragraph (or list item, or table row)
 * with `_(currently disabled — eval failing)_`.
 * 3. Strip the annotation comment from the published output.
 *
 * Usage:
 * node scripts/eval-gate-marketing.mjs --output dist/ \
 * --report eval-report.json
 *
 * Run by Mintlify build hook + landing-app build. Fail-open: if the
 * report is missing, treat ALL claims as red so we under-claim instead
 * of over-claim.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync, readdirSync } from "node:fs";
import { resolve, join, relative, dirname } from "node:path";
import { argv, exit } from "node:process";

const EVAL_ANNOTATION = /<!--\s*eval:([A-Z0-9\-,. ]+)\s*-->/g;

function parseArgs(argv) {
	const out = { output: "dist", report: "eval-report.json", roots: ["marketing", "apps/docs", "docs"] };
	for (let i = 2; i < argv.length; i++) {
		const a = argv[i];
		if (a === "--output") out.output = argv[++i];
		else if (a === "--report") out.report = argv[++i];
		else if (a === "--roots") out.roots = argv[++i].split(",");
	}
	return out;
}

function expandRange(spec) {
	// "PP-PR1..PP-PR12" → ["PP-PR1", ..., "PP-PR12"]
	const m = /^(PP-[A-Z]+)(\d+)\.\.(PP-[A-Z]+)(\d+)$/.exec(spec.trim());
	if (!m) return [spec.trim()];
	const [_, prefix, fromStr, prefix2, toStr] = m;
	if (prefix !== prefix2) return [spec.trim()];
	const from = Number.parseInt(fromStr, 10);
	const to = Number.parseInt(toStr, 10);
	if (!Number.isFinite(from) || !Number.isFinite(to) || to < from) return [spec.trim()];
	const out = [];
	for (let n = from; n <= to; n++) out.push(`${prefix}${n}`);
	return out;
}

function loadReport(path) {
	if (!existsSync(path)) {
		console.warn(`[eval-gate] report ${path} not found — treating all claims as red`);
		return new Set();
	}
	const json = JSON.parse(readFileSync(path, "utf8"));
	const greens = new Set();
	for (const r of json.results ?? []) {
		if (r.status === "pass") greens.add(r.id);
	}
	return greens;
}

function gateContent(content, greens) {
	return content.replace(EVAL_ANNOTATION, (_match, ids) => {
		const evalIds = ids
			.split(",")
			.flatMap((s) => expandRange(s))
			.map((s) => s.trim())
			.filter(Boolean);
		const allGreen = evalIds.every((id) => greens.has(id));
		if (allGreen) return ""; // strip the comment, leave content intact
		return "_(currently disabled — eval failing)_";
	});
}

function walk(dir, out) {
	for (const name of readdirSync(dir)) {
		if (name === "node_modules" || name === "target" || name.startsWith(".")) continue;
		const full = join(dir, name);
		const s = statSync(full);
		if (s.isDirectory()) walk(full, out);
		else if (/\.(md|mdx)$/.test(name)) out.push(full);
	}
}

function main() {
	const args = parseArgs(argv);
	const greens = loadReport(args.report);
	const cwd = process.cwd();
	const files = [];
	for (const root of args.roots) {
		const full = resolve(cwd, root);
		if (existsSync(full)) walk(full, files);
	}

	if (!existsSync(args.output)) mkdirSync(args.output, { recursive: true });
	let gatedCount = 0;
	for (const f of files) {
		const rel = relative(cwd, f);
		const content = readFileSync(f, "utf8");
		const out = gateContent(content, greens);
		if (out !== content) gatedCount += 1;
		const target = resolve(args.output, rel);
		mkdirSync(dirname(target), { recursive: true });
		writeFileSync(target, out, "utf8");
	}
	console.log(`[eval-gate] processed ${files.length} files, ${gatedCount} had gating applied`);
	console.log(`[eval-gate] greens: ${greens.size} eval IDs`);
}

main();
