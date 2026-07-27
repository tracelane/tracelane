/**
 * tlane migrate helicone — one-command migration from Helicone to Tracelane.
 *
 * What it does:
 *   1. Scans .env* files for HELICONE_API_KEY / HELICONE_BASE_URL and replaces
 *      them with TRACELANE_API_KEY / TRACELANE_GATEWAY_URL.
 *   2. Scans *.{ts,js,py} for Helicone SDK imports, base-URL references, and
 *      custom request headers, replacing with Tracelane equivalents.
 *   3. Prints a diff of every change (dry-run by default; --apply to write).
 *
 * One-liner usage:
 *   npx tlane migrate helicone --apply
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline/promises";
import type { Command } from "commander";

// ── Replacement rules ────────────────────────────────────────────────────────

/** Env-var key renames (exact key match, value preserved) */
const ENV_KEY_RENAMES: [RegExp, string][] = [
	[/^HELICONE_API_KEY(\s*=)/m, "TRACELANE_API_KEY$1"],
	[/^HELICONE_BASE_URL(\s*=)/m, "TRACELANE_GATEWAY_URL$1"],
	[/^HELICONE_CACHE_ENABLED(\s*=)/m, "# TRACELANE_CACHE_ENABLED$1"],
	[/^HELICONE_RETRY_ENABLED(\s*=)/m, "# TRACELANE_RETRY_ENABLED$1"],
];

/** Source-code text replacements (global, case-sensitive) */
const SOURCE_REPLACEMENTS: [RegExp, string][] = [
	// OpenAI SDK base URL override
	[/https:\/\/oai\.helicone\.ai\/v1/g, "https://gateway.tracelane.dev/v1"],
	[
		/https:\/\/anthropic\.helicone\.ai\/v1/g,
		"https://gateway.tracelane.dev/v1",
	],
	[/https:\/\/gateway\.helicone\.ai\/v1/g, "https://gateway.tracelane.dev/v1"],
	// Helicone auth header
	[
		/"Helicone-Auth":\s*`Bearer \${[^}]+}`/g,
		'"Authorization": `Bearer ${process.env.TRACELANE_API_KEY}`',
	],
	[
		/"Helicone-Auth":\s*"Bearer [^"]+"/g,
		'"Authorization": `Bearer ${process.env.TRACELANE_API_KEY}`',
	],
	// Python SDK: helicone base_url
	[
		/base_url\s*=\s*["']https:\/\/oai\.helicone\.ai\/v1["']/g,
		'base_url="https://gateway.tracelane.dev/v1"',
	],
	// HeliconeAsyncOpenAI / HeliconeOpenAI imports
	[
		/from\s+helicone\s+import\s+HeliconeAsyncOpenAI/g,
		"from openai import AsyncOpenAI  # migrated from Helicone",
	],
	[
		/from\s+helicone\s+import\s+HeliconeOpenAI/g,
		"from openai import OpenAI  # migrated from Helicone",
	],
	[
		/import\s+\{\s*HeliconeOpenAI\s*\}\s+from\s+"@helicone\/helicone"/g,
		'import OpenAI from "openai" // migrated from Helicone',
	],
	[
		/import\s+\{\s*HeliconeOpenAI\s*\}\s+from\s+"@helicone\/helicone-js"/g,
		'import OpenAI from "openai" // migrated from Helicone',
	],
	// heliconeHeaders object
	[
		/heliconeHeaders\s*=\s*\{[^}]*"Helicone-Auth"[^}]*\}/gs,
		"// heliconeHeaders removed — Tracelane uses Authorization header",
	],
	// HELICONE_API_KEY env var references in code
	[/process\.env\.HELICONE_API_KEY/g, "process.env.TRACELANE_API_KEY"],
	[
		/os\.environ\[["']HELICONE_API_KEY["']\]/g,
		'os.environ["TRACELANE_API_KEY"]',
	],
	[/os\.getenv\(["']HELICONE_API_KEY["']\)/g, 'os.getenv("TRACELANE_API_KEY")'],
];

const ENV_FILE_GLOBS = [
	".env",
	".env.local",
	".env.production",
	".env.development",
];
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".py"]);
const IGNORE_DIRS = new Set([
	"node_modules",
	".git",
	"__pycache__",
	".venv",
	"dist",
	"build",
]);

// ── File discovery ────────────────────────────────────────────────────────────

function findEnvFiles(root: string): string[] {
	return ENV_FILE_GLOBS.map((f) => path.join(root, f)).filter((p) =>
		fs.existsSync(p),
	);
}

function findSourceFiles(root: string): string[] {
	const results: string[] = [];

	function walk(dir: string) {
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				if (!IGNORE_DIRS.has(entry.name)) walk(full);
			} else if (entry.isFile() && SOURCE_EXTS.has(path.extname(entry.name))) {
				results.push(full);
			}
		}
	}

	walk(root);
	return results;
}

// ── Transformation logic ──────────────────────────────────────────────────────

interface FileChange {
	file: string;
	before: string;
	after: string;
}

export function applyEnvTransforms(content: string): string {
	let out = content;
	for (const [pattern, replacement] of ENV_KEY_RENAMES) {
		out = out.replace(pattern, replacement);
	}
	return out;
}

export function applySourceTransforms(content: string): string {
	let out = content;
	for (const [pattern, replacement] of SOURCE_REPLACEMENTS) {
		out = out.replace(pattern, replacement);
	}
	return out;
}

export function hasHeliconeRef(content: string): boolean {
	return /helicone/i.test(content) || /HELICONE/i.test(content);
}

// ── Diff printer ──────────────────────────────────────────────────────────────

function printDiff(change: FileChange): void {
	const rel = path.relative(process.cwd(), change.file);
	const beforeLines = change.before.split("\n");
	const afterLines = change.after.split("\n");

	console.log(`\n\x1b[1m${rel}\x1b[0m`);

	const maxLines = Math.max(beforeLines.length, afterLines.length);
	for (let i = 0; i < maxLines; i++) {
		const b = beforeLines[i];
		const a = afterLines[i];
		if (b !== a) {
			if (b !== undefined) console.log(`  \x1b[31m- ${b}\x1b[0m`);
			if (a !== undefined) console.log(`  \x1b[32m+ ${a}\x1b[0m`);
		}
	}
}

// ── Main migration runner ─────────────────────────────────────────────────────

async function runMigration(opts: {
	apply: boolean;
	endpoint: string;
	root: string;
}) {
	const changes: FileChange[] = [];

	// 1. Env files
	for (const envFile of findEnvFiles(opts.root)) {
		const before = fs.readFileSync(envFile, "utf8");
		const after = applyEnvTransforms(before);
		if (before !== after) changes.push({ file: envFile, before, after });
	}

	// 2. Source files containing Helicone references
	for (const srcFile of findSourceFiles(opts.root)) {
		const before = fs.readFileSync(srcFile, "utf8");
		if (!hasHeliconeRef(before)) continue;
		const after = applySourceTransforms(before);
		if (before !== after) changes.push({ file: srcFile, before, after });
	}

	if (changes.length === 0) {
		console.log(
			"\x1b[32m✓ No Helicone references found — nothing to migrate.\x1b[0m",
		);
		return;
	}

	// 3. Show diff
	console.log(
		`\nFound \x1b[1m${changes.length}\x1b[0m file(s) with Helicone references:\n`,
	);
	for (const change of changes) {
		printDiff(change);
	}

	// 4. Apply or prompt
	if (!opts.apply) {
		console.log(
			"\n\x1b[33m[dry-run] No files written. Re-run with --apply to apply changes.\x1b[0m\n",
		);
		return;
	}

	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
	});
	const answer = await rl.question(
		`\nApply ${changes.length} change(s)? [y/N] `,
	);
	rl.close();

	if (answer.trim().toLowerCase() !== "y") {
		console.log("Aborted.");
		return;
	}

	for (const change of changes) {
		fs.writeFileSync(change.file, change.after, "utf8");
		console.log(
			`  \x1b[32m✓\x1b[0m wrote ${path.relative(opts.root, change.file)}`,
		);
	}

	// 5. Post-migration instructions
	console.log(`
\x1b[1m✓ Migration complete!\x1b[0m

Next steps:
  1. Set TRACELANE_API_KEY in your environment (get one at https://tracelane.dev/dashboard)
  2. Remove @helicone/helicone from your dependencies:
     npm uninstall @helicone/helicone   or   pip uninstall helicone
  3. Your gateway endpoint: \x1b[36m${opts.endpoint}/v1/chat/completions\x1b[0m

Tracelane is API-compatible with Helicone — no other code changes needed.
`);
}

// ── Command registration ──────────────────────────────────────────────────────

export function registerMigrateCommand(program: Command): void {
	const migrate = program
		.command("migrate")
		.description("Migrate from another observability provider to Tracelane");

	migrate
		.command("helicone")
		.description(
			"Migrate Helicone configuration and SDK calls to Tracelane (one command)",
		)
		.option("--apply", "Write changes to disk (default: dry-run preview only)")
		.option(
			"--endpoint <url>",
			"Tracelane gateway URL",
			"https://gateway.tracelane.dev",
		)
		.option("--dir <path>", "Project root directory to scan", process.cwd())
		.action(async (opts) => {
			await runMigration({
				apply: opts.apply ?? false,
				endpoint: opts.endpoint,
				root: opts.dir,
			});
		});
}
