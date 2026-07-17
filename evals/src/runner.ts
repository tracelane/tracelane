/**
 * Eval suite runner — wraps vitest with suite filtering.
 *
 * Usage:
 *   pnpm eval:run --suite=all
 *   pnpm eval:run --suite=pp
 *   pnpm eval:run --suite=ft
 *
 * Exits with vitest's exit code so CI gates work. Surfaces spawn failures
 * loudly — earlier version did `process.exit(result.status ?? 0)` which
 * masked silent ENOENT (the bare `.bin/vitest` path doesn't exist on
 * Windows; only `vitest.cmd` does).
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";

// Resolve repo root from this source file. tsconfig is NodeNext + the
// package has no `"type": "module"`, so TypeScript treats this file as
// CommonJS and `import.meta` is not available. The bare CJS globals
// `__filename` / `__dirname` are provided by Node at runtime; we
// reference them directly to keep this file CJS-clean.
declare const __filename: string;
declare const __dirname: string;
const root = resolve(__dirname, "..");
void __filename;

const suiteArg = process.argv.find((a) => a.startsWith("--suite="));
const suite = suiteArg?.split("=")[1] ?? "all";

// Filter strings passed to vitest — matched against full file paths.
const SUITE_FILTER: Record<string, string> = {
	all: ".eval.ts",
	ft: "fault-tolerance",
	gc: "gateway-correctness",
	is: "ingest-schema",
	pp: "pain-points",
	pir: "pii-redaction",
	pi: "prompt-injection",
};

// Unknown suite = hard error, never a silent run-everything fallback
// (L3 residual audit 2026-07-03: `--suite=gateway` in the blue-green deploy
// script fell through to ALL evals — a wrong suite name must fail loudly,
// especially when the caller is a deploy gate).
const filter = SUITE_FILTER[suite];
if (!filter) {
	console.error(
		`evals/runner: unknown suite "${suite}" — valid suites: ${Object.keys(SUITE_FILTER).join(", ")}`,
	);
	process.exit(2);
}

// Resolve the vitest binary cross-platform. On Windows pnpm/npm install a
// `.cmd` shim alongside the bare `vitest` script — spawning the bare path
// returns ENOENT and the previous runner did `process.exit(result.status ?? 0)`,
// which masked the failure as a silent success.
const isWindows = process.platform === "win32";
const binDir = resolve(root, "node_modules", ".bin");
const candidates = isWindows
	? [
			resolve(binDir, "vitest.cmd"),
			resolve(binDir, "vitest.CMD"),
			resolve(binDir, "vitest.ps1"),
			resolve(binDir, "vitest.bat"),
			resolve(binDir, "vitest"),
		]
	: [resolve(binDir, "vitest")];

const vitestBin = candidates.find((p) => existsSync(p));
if (!vitestBin) {
	console.error(
		`evals/runner: could not find vitest binary in ${binDir}. ` +
			`Tried: ${candidates.join(", ")}. ` +
			`Run 'pnpm install' from the workspace root first.`,
	);
	process.exit(2);
}

console.log(
	`evals/runner: suite=${suite} filter='${filter}' bin=${vitestBin}`,
);

const result = spawnSync(vitestBin, ["run", filter], {
	cwd: root,
	stdio: "inherit",
	env: { ...process.env },
	// `shell: true` lets Windows resolve .cmd shims through cmd.exe so we
	// don't have to pass the explicit cmd.exe wrapper ourselves.
	shell: isWindows,
});

if (result.error) {
	console.error(`evals/runner: spawn failed — ${result.error.message}`);
	process.exit(1);
}

if (result.status === null) {
	console.error(
		`evals/runner: vitest exited with no status (signal=${result.signal ?? "none"}).`,
	);
	process.exit(1);
}

process.exit(result.status);
