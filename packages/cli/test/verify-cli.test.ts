/**
 * tlane verify CLI smoke tests.
 *
 * Spawns the actual tlane bin (built or via tsx) and asserts the
 * command's exit-code contract:
 *   0 — ledger verifies cleanly
 *   1 — verification failure (hash chain or signature)
 *   2 — I/O error (missing file etc.)
 *
 * Uses the audit-ledger conformance vectors in evals/audit-ledger/
 * which are shared with the verifier-{rust,python,typescript} suites.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..", "..");
const vectorsDir = resolve(repoRoot, "evals", "audit-ledger");

function runCli(...args: string[]): {
	status: number | null;
	stdout: string;
	stderr: string;
} {
	const cliEntry = resolve(__dirname, "..", "src", "index.ts");
	// Invoke the local devDependency `tsx` directly from this package's
	// node_modules rather than relying on `npx`. CI runs pnpm without
	// hoisting, so `npx tsx` from the repo root resolves nothing and the
	// child exits with code 127. The local binary path is hermetic.
	const pkgRoot = resolve(__dirname, "..");
	const tsxBin = resolve(
		pkgRoot,
		"node_modules",
		".bin",
		process.platform === "win32" ? "tsx.cmd" : "tsx",
	);
	const result = spawnSync(tsxBin, [cliEntry, ...args], {
		cwd: repoRoot,
		encoding: "utf-8",
		shell: process.platform === "win32",
	});
	return {
		status: result.status,
		stdout: result.stdout?.toString() ?? "",
		stderr: result.stderr?.toString() ?? "",
	};
}

describe("tlane verify CLI exit-code contract", () => {
	const goodPath = resolve(vectorsDir, "good.ndjson");
	const tamperedPath = resolve(vectorsDir, "tampered.ndjson");
	const missingPath = resolve(vectorsDir, "this-file-does-not-exist.ndjson");

	it.runIf(existsSync(goodPath))(
		"exits 0 on a clean ledger (--offline)",
		() => {
			const { status, stdout } = runCli(
				"verify",
				goodPath,
				"--offline",
			);
			expect(status).toBe(0);
			expect(stdout).toMatch(/PASS|hash_chain_valid:\s*true/);
		},
		60_000,
	);

	it.runIf(existsSync(tamperedPath))(
		"exits 1 on a tampered ledger (--offline)",
		() => {
			const { status, stdout } = runCli(
				"verify",
				tamperedPath,
				"--offline",
			);
			expect(status).toBe(1);
			expect(stdout).toMatch(/FAIL|hash_chain_valid:\s*false/);
		},
		60_000,
	);

	it("exits 2 when the ledger file does not exist", () => {
		const { status, stderr } = runCli("verify", missingPath, "--offline");
		expect(status).toBe(2);
		expect(stderr).toMatch(/file not found/i);
	});
});
