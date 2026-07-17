/**
 * tlane eval — pain-point eval suite commands.
 *
 *   tlane eval list   — parse evals/pain-points/INDEX.md and render each
 *                       eval's id, status, and title.
 *   tlane eval run    — run the eval suite via `pnpm eval:run --suite=<x>`
 *                       (use --dry-run to print the command without executing).
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import type { Command } from "commander";

export interface EvalEntry {
	id: string;
	title: string;
	status: string;
}

/**
 * Parse the pain-point INDEX.md markdown tables into eval entries.
 *
 * Rows look like `| **PP-G1** | **Title** | **🟢 status** | ref |`. Header and
 * separator rows are skipped because their first cell is not a `PP-…` id.
 */
export function parseEvalIndex(markdown: string): EvalEntry[] {
	const entries: EvalEntry[] = [];
	for (const line of markdown.split("\n")) {
		if (!line.trimStart().startsWith("|")) continue;
		const cells = line
			.split("|")
			.slice(1, -1)
			.map((c) => c.replace(/\*\*/g, "").trim());
		const id = cells[0] ?? "";
		if (!/^PP-[A-Z0-9-]+$/.test(id)) continue;
		entries.push({
			id,
			title: cells[1] ?? "",
			status: cells[2] ?? "",
		});
	}
	return entries;
}

/** Walk up from `startDir` to the repo root (CLAUDE.md), return the INDEX path. */
export function findEvalIndex(startDir: string): string | null {
	let dir = startDir;
	for (let i = 0; i < 8; i++) {
		const candidate = join(dir, "evals", "pain-points", "INDEX.md");
		if (existsSync(candidate)) return candidate;
		if (existsSync(join(dir, "CLAUDE.md"))) {
			return existsSync(candidate) ? candidate : null;
		}
		const parent = resolve(dir, "..");
		if (parent === dir) break;
		dir = parent;
	}
	return null;
}

/** Walk up from `startDir` to find the `evals/pain-points` directory, if present. */
export function findEvalDir(startDir: string): string | null {
	let dir = startDir;
	for (let i = 0; i < 8; i++) {
		const candidate = join(dir, "evals", "pain-points");
		if (existsSync(candidate)) return candidate;
		const parent = resolve(dir, "..");
		if (parent === dir) break;
		dir = parent;
	}
	return null;
}

export function registerEvalCommand(program: Command): void {
	const evalCmd = program.command("eval").description("Eval suite commands");

	evalCmd
		.command("list")
		.description("List pain-point evals and their status")
		.action(() => {
			const indexPath = findEvalIndex(process.cwd());
			if (indexPath) {
				const entries = parseEvalIndex(readFileSync(indexPath, "utf8"));
				for (const e of entries) {
					// Status can be long; show the first clause for a compact list.
					const shortStatus = (e.status.split(";")[0] ?? "").slice(0, 32);
					console.log(
						`${e.id.padEnd(10)} ${shortStatus.padEnd(34)} ${e.title}`,
					);
				}
				console.log(`\n${entries.length} evals`);
				return;
			}
			// No INDEX.md (e.g. a published OSS checkout) — list the eval files directly.
			const dir = findEvalDir(process.cwd());
			if (!dir) {
				console.error("eval suite not found from this directory");
				process.exit(1);
				return;
			}
			const ids = readdirSync(dir)
				.filter((f) => f.endsWith(".eval.ts"))
				.map((f) => f.replace(/\.eval\.ts$/, ""))
				.sort();
			for (const id of ids) console.log(id);
			console.log(`\n${ids.length} evals`);
		});

	evalCmd
		.command("run")
		.description("Run the eval suite")
		.option(
			"--suite <name>",
			"Eval suite to run: all|gateway|ingest|predictive",
			"all",
		)
		.option("--dry-run", "Print the command without executing")
		.action((opts) => {
			const args = ["eval:run", `--suite=${opts.suite}`];
			console.log(`pnpm ${args.join(" ")}`);
			if (opts.dryRun) return;
			const result = spawnSync("pnpm", args, { stdio: "inherit" });
			process.exit(result.status ?? 1);
		});
}
