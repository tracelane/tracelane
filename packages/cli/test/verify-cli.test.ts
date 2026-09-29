import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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
import { describe, expect, it } from "vitest";

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
			const { status, stdout } = runCli("verify", goodPath, "--offline");
			expect(status).toBe(0);
			expect(stdout).toMatch(/PASS|hash_chain_valid:\s*true/);
		},
		60_000,
	);

	it.runIf(existsSync(tamperedPath))(
		"exits 1 on a tampered ledger (--offline)",
		() => {
			const { status, stdout } = runCli("verify", tamperedPath, "--offline");
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

// B-483 (2026-09-21): a row inside NO anchor batch although a LATER batch of the same
// tenant exists is a HOLE — unsigned and un-anchored — and the CLI must never print PASS
// over one. The verifier counts it (`rows_uncovered_by_anchors`); the CLI gates on it.
describe("tlane verify refuses a ledger with an anchor-coverage hole (B-483)", () => {
	const goodPath = resolve(vectorsDir, "good.ndjson");

	it("verdictOf: a nonzero uncovered count is FAIL even when chain + signatures pass", async () => {
		const { verdictOf } = await import("../src/commands/verify.js");
		const clean = {
			hash_chain_valid: true,
			signatures_valid: true,
			anchors_unverified: 0,
			rows_uncovered_by_anchors: 0,
		};
		expect(verdictOf(clean)).toBe("PASS");
		expect(verdictOf({ ...clean, rows_uncovered_by_anchors: 100 })).toBe(
			"FAIL",
		);
		expect(verdictOf({ ...clean, anchors_unverified: 1 })).toBe("INCOMPLETE");
	});

	it.runIf(existsSync(goodPath))(
		"counts and prints the hole; exit 1",
		async () => {
			const { mkdtempSync, readFileSync, writeFileSync } = await import(
				"node:fs"
			);
			const { tmpdir } = await import("node:os");
			const { join } = await import("node:path");
			// good.ndjson: 100 rows for one tenant. Two anchor records leave 10..19 in no
			// batch (a hole of 10) and 30..99 past the last anchor (a tail of 70).
			const tenant = (
				JSON.parse(readFileSync(goodPath, "utf-8").split("\n")[0]) as {
					tenant_id: string;
				}
			).tenant_id;
			const anchor = (lo: number, hi: number) =>
				JSON.stringify({
					type: "anchor",
					tenant_id: tenant,
					batch_start_seq: lo,
					batch_end_seq: hi,
				});
			const dir = mkdtempSync(join(tmpdir(), "tlane-b483-"));
			const holePath = join(dir, "hole.ndjson");
			writeFileSync(
				holePath,
				`${readFileSync(goodPath, "utf-8").trimEnd()}\n${anchor(0, 9)}\n${anchor(20, 29)}\n`,
			);

			const json = runCli("verify", holePath, "--json");
			expect(json.status).toBe(1);
			const report = JSON.parse(json.stdout) as {
				rows_uncovered_by_anchors: number;
				rows_unanchored_tail: number;
				errors: Array<{ kind: string; detail: string }>;
			};
			expect(report.rows_uncovered_by_anchors).toBe(10);
			expect(report.rows_unanchored_tail).toBe(70);
			expect(
				report.errors.find((e) => e.kind === "anchor_coverage_gap")?.detail,
			).toContain("10..19");

			const human = runCli("verify", holePath);
			expect(human.status).toBe(1);
			expect(human.stdout).toMatch(/rows_uncovered_by_anchors:\s*10/);
			expect(human.stdout).toMatch(/rows_unanchored_tail:\s*70/);
			expect(human.stdout).not.toMatch(/tlane verify: PASS/);
		},
		120_000,
	);
});

// AUD-29 (2026-09-28): a workspace's batches signed by Tracelane's PLATFORM key before it
// had its own key verify and are counted apart; a platform-signed batch AFTER the
// workspace key is FAIL. Shared vectors: evals/audit-ledger/generate_platform_key_vectors.py.
describe("tlane verify — AUD-29 platform-key trust root", () => {
	const metaPath = resolve(vectorsDir, "platform-key-vectors.meta.json");
	const meta = existsSync(metaPath)
		? (JSON.parse(readFileSync(metaPath, "utf-8")) as Record<string, string>)
		: {};

	it.runIf(existsSync(metaPath))(
		"PASS with the platform-signed prefix named and counted",
		() => {
			const { status, stdout } = runCli(
				"verify",
				resolve(vectorsDir, "platform-then-workspace.ndjson"),
				"--tenant-pubkey",
				meta.workspace_ed25519_pubkey_b64 ?? "",
				"--platform-pubkey",
				meta.platform_ed25519_pubkey_b64 ?? "",
			);
			expect(stdout).toMatch(/tlane verify: PASS/);
			expect(stdout).toMatch(
				/platform_signed_batches: 1 \(verified against Tracelane's platform key — --platform-pubkey/,
			);
			expect(status).toBe(0);
		},
		60_000,
	);

	it.runIf(existsSync(metaPath))(
		"FAIL when the published takeover seq is reached with no workspace batch in view",
		() => {
			const { status, stdout } = runCli(
				"verify",
				resolve(vectorsDir, "platform-only.ndjson"),
				"--tenant-pubkey",
				meta.workspace_ed25519_pubkey_b64 ?? "",
				"--platform-pubkey",
				meta.platform_ed25519_pubkey_b64 ?? "",
				"--workspace-key-since-seq",
				"5",
			);
			expect(stdout).toMatch(/platform_key_after_workspace_key/);
			expect(status).toBe(1);
		},
		60_000,
	);

	it.runIf(existsSync(metaPath))(
		"FAIL when the platform key signs after the workspace key",
		() => {
			const { status, stdout } = runCli(
				"verify",
				resolve(vectorsDir, "workspace-then-platform.ndjson"),
				"--tenant-pubkey",
				meta.workspace_ed25519_pubkey_b64 ?? "",
				"--platform-pubkey",
				meta.platform_ed25519_pubkey_b64 ?? "",
			);
			expect(stdout).toMatch(/platform_key_after_workspace_key/);
			expect(status).toBe(1);
		},
		60_000,
	);
});
