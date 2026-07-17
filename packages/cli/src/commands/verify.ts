/**
 * tlane verify — recompute and verify a Tracelane tamper-evident audit ledger.
 *
 * Wraps the reference TypeScript verifier in `@tracelanedev/audit-verifier`.
 * The Rust and Python verifiers (under `packages/`) are alternative
 * implementations for non-Node toolchains; on the current `v2.1` export
 * format (ADR-050) all three hash the verbatim canonical payload string, so
 * they agree by construction. This command is the primary CLI surface.
 *
 * Format is auto-detected per row via the export's `format` marker — no flag
 * needed. Legacy `v2` packs (nested-object payloads) still verify via the
 * read-only re-canonicalize path.
 *
 * Usage:
 *   tlane verify ./audit.ndjson                         # hash chain only
 *   tlane verify ./audit.ndjson --tenant-pubkey <b64>   # + signatures + anchors (ADR-062)
 *   tlane verify ./audit.ndjson --json
 *
 * Exit codes:
 *   0 — all checks passed
 *   1 — at least one logical verification failure (hash chain or signature)
 *   2 — file not found / I/O error
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import type { Command } from "commander";

// Resolved at runtime against the `@tracelanedev/audit-verifier` workspace
// package. Importing it dynamically avoids a hard build dependency on the
// verifier when this CLI is bundled — `pnpm -F @tracelanedev/cli build` only
// needs the verifier's published types.
type VerifyLedger = (
	path: string,
	options?: { offline?: boolean; tenantPubkey?: Uint8Array },
) => Promise<{
	ledger_path: string;
	rows_seen: number;
	hash_chain_valid: boolean;
	signatures_valid: boolean;
	rekor_anchors_seen: number;
	rekor_anchors_resolved: number;
	anchors_included: number;
	strip_detected: boolean;
	errors: Array<{ seq: number | null; kind: string; detail: string }>;
}>;

export function registerVerifyCommand(program: Command): void {
	program
		.command("verify <ledger>")
		.description(
			"Verify a Tracelane tamper-evident audit ledger (NDJSON format)",
		)
		.option(
			"--offline",
			"(deprecated no-op) verification is always offline",
			false,
		)
		.option(
			"--tenant-pubkey <base64>",
			"Trusted tenant Ed25519 pubkey (base64) from your Tracelane dashboard (Settings → Audit signing key, or GET /v1/audit/pubkey). Enables signature + public-anchor verification (ADR-062); without it, only the hash chain is checked.",
		)
		.option("--json", "Emit the verification report as JSON to stdout", false)
		.action(
			async (
				ledgerArg: string,
				opts: { offline?: boolean; tenantPubkey?: string; json?: boolean },
			) => {
				const path = resolve(process.cwd(), ledgerArg);
				if (!existsSync(path)) {
					process.stderr.write(`tlane verify: file not found: ${path}\n`);
					process.exit(2);
				}

				let verifyLedger: VerifyLedger;
				try {
					// Variable indirection so `tsc --noEmit` doesn't try to
					// resolve the workspace package at compile time. The
					// runtime import is handled by pnpm workspace linking.
					const verifierPkg = "@tracelanedev/audit-verifier/node";
					const mod = (await import(verifierPkg)) as {
						verifyLedger: VerifyLedger;
					};
					verifyLedger = mod.verifyLedger;
				} catch (err) {
					process.stderr.write(
						`tlane verify: @tracelanedev/audit-verifier not installed. Run 'pnpm -w install' first.\n${(err as Error).message}\n`,
					);
					process.exit(2);
				}

				let tenantPubkey: Uint8Array | undefined;
				if (opts.tenantPubkey) {
					tenantPubkey = Uint8Array.from(
						Buffer.from(opts.tenantPubkey, "base64"),
					);
					if (tenantPubkey.length !== 32) {
						process.stderr.write(
							`tlane verify: --tenant-pubkey must be a base64 32-byte Ed25519 key (got ${tenantPubkey.length} bytes)\n`,
						);
						process.exit(2);
					}
				}

				const report = await verifyLedger(path, {
					offline: opts.offline,
					tenantPubkey,
				});

				if (opts.json) {
					process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
				} else {
					const status =
						report.hash_chain_valid && report.signatures_valid
							? "PASS"
							: "FAIL";
					process.stdout.write(`tlane verify: ${status}\n`);
					process.stdout.write(
						`  ledger:                ${report.ledger_path}\n`,
					);
					process.stdout.write(
						`  rows_seen:             ${report.rows_seen}\n`,
					);
					process.stdout.write(
						`  hash_chain_valid:      ${report.hash_chain_valid}\n`,
					);
					process.stdout.write(
						`  signatures_valid:      ${report.signatures_valid}\n`,
					);
					process.stdout.write(
						`  rekor_anchors_seen:    ${report.rekor_anchors_seen}\n`,
					);
					process.stdout.write(
						`  rekor_anchors_resolved:${report.rekor_anchors_resolved}\n`,
					);
					process.stdout.write(
						// Always name the log with the count — a Rekor v2 index is only
						// meaningful WITH its log (v2 `log2025-1` and the legacy v1 log have
						// independent index spaces).
						`  anchors_included:      ${report.anchors_included}${report.anchors_included > 0 ? " (Sigstore Rekor v2 · log2025-1.rekor.sigstore.dev)" : ""}\n`,
					);
					if (report.strip_detected) {
						process.stdout.write(
							"  strip_detected:        true (a batch claims anchored but its proof is missing)\n",
						);
					}
					if (report.errors.length > 0) {
						process.stdout.write(`  errors (${report.errors.length}):\n`);
						for (const e of report.errors.slice(0, 10)) {
							const seq = e.seq === null ? "—" : e.seq.toString();
							process.stdout.write(
								`    - seq=${seq.padEnd(6)} ${e.kind}: ${e.detail}\n`,
							);
						}
						if (report.errors.length > 10) {
							process.stdout.write(
								`    ... and ${report.errors.length - 10} more\n`,
							);
						}
					}
				}

				process.exit(
					report.hash_chain_valid && report.signatures_valid ? 0 : 1,
				);
			},
		);
}
