/**
 * tlane verify — recompute and verify a Tracelane tamper-evident audit ledger.
 *
 * Wraps the reference TypeScript verifier in `@tracelanedev/audit-verifier`.
 * The Rust and Python verifiers (under `packages/`) are alternative
 * implementations for non-Node toolchains; on the current `v2.1` export
 * format (v2.1) all three hash the verbatim canonical payload string, so
 * they agree by construction. This command is the primary CLI surface.
 *
 * Format is auto-detected per row via the export's `format` marker — no flag
 * needed. Legacy `v2` packs (nested-object payloads) still verify via the
 * read-only re-canonicalize path.
 *
 * Usage:
 *   tlane verify ./audit.ndjson                         # hash chain only
 *   tlane verify ./audit.ndjson --tenant-pubkey <b64>   # + signatures + anchors
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
	options?: {
		offline?: boolean;
		tenantPubkey?: Uint8Array;
		platformPubkey?: Uint8Array;
		platformPubkeys?: Uint8Array[];
		workspaceKeySinceSeq?: number;
	},
) => Promise<{
	ledger_path: string;
	rows_seen: number;
	hash_chain_valid: boolean;
	signatures_valid: boolean;
	rekor_anchors_seen: number;
	rekor_anchors_resolved: number;
	anchors_included: number;
	anchors_unverified: number;
	strip_detected: boolean;
	/** B-483 — rows inside NO anchor batch although a later batch exists: a hole
	 * below the anchor watermark. Nonzero is never PASS. */
	rows_uncovered_by_anchors: number;
	/** B-483 — rows past the tenant's last anchor: the ordinary tail, not a hole. */
	rows_unanchored_tail: number;
	/** AUD-29 — batches verified against Tracelane's PLATFORM key, not the workspace key. */
	platform_signed_batches?: number;
	platform_signed_ranges?: Array<{ start_seq: number; end_seq: number }>;
	errors: Array<{ seq: number | null; kind: string; detail: string }>;
}>;

/**
 * The verdict, in one place so a test can hold it (B-483, 2026-09-21).
 * INCOMPLETE — anchor records were present but never verified (no trusted key);
 * FAIL — the chain, a signature, or anchor COVERAGE is broken; PASS — all three hold.
 * A hole below the anchor watermark is unsigned and un-anchored: the rows exist, the
 * chain over them may even hash, and nobody can prove they were not rewritten. The
 * Rust CLI (`crates/tracelane-audit-cli`) applies the identical predicate.
 */
export function verdictOf(report: {
	hash_chain_valid: boolean;
	signatures_valid: boolean;
	anchors_unverified: number;
	rows_uncovered_by_anchors?: number;
}): "PASS" | "FAIL" | "INCOMPLETE" {
	if (report.anchors_unverified > 0) {
		return "INCOMPLETE";
	}
	return report.hash_chain_valid &&
		report.signatures_valid &&
		(report.rows_uncovered_by_anchors ?? 0) === 0
		? "PASS"
		: "FAIL";
}

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
			"Trusted tenant Ed25519 pubkey (base64) from your Tracelane dashboard (Settings → Audit signing key, or GET /v1/audit/pubkey). Enables signature + public-anchor verification; without it, only the hash chain is checked.",
		)
		.option(
			"--platform-pubkey <base64>",
			"Tracelane's platform Ed25519 pubkey (base64) — signs a workspace's batches before it has its own key (GET /v1/audit/platform-pubkey). Defaults to the key pinned in this release.",
		)
		.option(
			"--workspace-key-since-seq <seq>",
			"The first ledger seq your workspace key signed (workspace_key_since_seq from GET /v1/audit/pubkey?tenant_id=…). A platform-signed batch at or past it FAILS even when the range holds no workspace-signed batch.",
		)
		.option("--json", "Emit the verification report as JSON to stdout", false)
		.action(
			async (
				ledgerArg: string,
				opts: {
					offline?: boolean;
					tenantPubkey?: string;
					platformPubkey?: string;
					workspaceKeySinceSeq?: string;
					json?: boolean;
				},
			) => {
				const path = resolve(process.cwd(), ledgerArg);
				if (!existsSync(path)) {
					process.stderr.write(`tlane verify: file not found: ${path}\n`);
					process.exit(2);
				}

				let verifyLedger: VerifyLedger;
				let pinnedPlatformB64: readonly string[] = [];
				try {
					// Variable indirection so `tsc --noEmit` doesn't try to
					// resolve the workspace package at compile time. The
					// runtime import is handled by pnpm workspace linking.
					const verifierPkg = "@tracelanedev/audit-verifier/node";
					const mod = (await import(verifierPkg)) as {
						verifyLedger: VerifyLedger;
						TRACELANE_PLATFORM_PUBKEYS_B64?: readonly string[];
					};
					verifyLedger = mod.verifyLedger;
					pinnedPlatformB64 = mod.TRACELANE_PLATFORM_PUBKEYS_B64 ?? [];
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

				// AUD-29: the platform key — an explicit flag wins; otherwise EVERY key
				// pinned in this verifier release (a rotation keeps the retired key).
				// Never a key read from the ledger itself.
				const platformSource = opts.platformPubkey
					? "--platform-pubkey"
					: pinnedPlatformB64.length > 0
						? "pinned in this release"
						: "none";
				const platformPubkeys: Uint8Array[] = [];
				for (const b64 of opts.platformPubkey
					? [opts.platformPubkey]
					: pinnedPlatformB64) {
					const k = Uint8Array.from(Buffer.from(b64, "base64"));
					if (k.length !== 32) {
						process.stderr.write(
							`tlane verify: --platform-pubkey must be a base64 32-byte Ed25519 key (got ${k.length} bytes)\n`,
						);
						process.exit(2);
					}
					platformPubkeys.push(k);
				}
				let workspaceKeySinceSeq: number | undefined;
				if (opts.workspaceKeySinceSeq !== undefined) {
					workspaceKeySinceSeq = Number(opts.workspaceKeySinceSeq);
					if (
						!Number.isSafeInteger(workspaceKeySinceSeq) ||
						workspaceKeySinceSeq < 0
					) {
						process.stderr.write(
							"tlane verify: --workspace-key-since-seq must be a non-negative integer\n",
						);
						process.exit(2);
					}
				}

				const report = await verifyLedger(path, {
					offline: opts.offline,
					tenantPubkey,
					platformPubkeys,
					workspaceKeySinceSeq,
				});

				// FAIL CLOSED (P0, 2026-08-07). Anchor records present but skipped
				// for want of a trusted key mean signature + anchor verification
				// NEVER RAN. Reporting PASS there printed `signatures_valid: true`
				// over a FORGED anchor — proven against
				// `evals/audit-ledger/forged-anchor.ndjson`. `signatures_valid` is
				// vacuously true in chain-only mode; the verifier's own contract
				// says never gate on it alone.
				const unchecked = report.anchors_unverified > 0;
				const status = verdictOf(report);

				if (opts.json) {
					process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
				} else {
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
						`  signatures_valid:      ${unchecked ? "NOT CHECKED — no --tenant-pubkey" : report.signatures_valid}\n`,
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
					// B-483: a nonzero hole count is printed with what it means, because a
					// reader who sees only the number reads "not anchored yet" — it is "never".
					process.stdout.write(
						`  rows_uncovered_by_anchors: ${report.rows_uncovered_by_anchors ?? 0}${(report.rows_uncovered_by_anchors ?? 0) > 0 ? " (a HOLE below the anchor watermark — unsigned, un-anchored; never PASS)" : ""}\n`,
					);
					process.stdout.write(
						`  rows_unanchored_tail:  ${report.rows_unanchored_tail ?? 0}${(report.rows_unanchored_tail ?? 0) > 0 ? " (past the last anchor — the next batch is still filling)" : ""}\n`,
					);
					const platformSigned = report.platform_signed_batches ?? 0;
					process.stdout.write(
						`  platform_signed_batches: ${platformSigned}${platformSigned > 0 ? ` (verified against Tracelane's platform key — ${platformSource} — before this workspace had its own key; Tracelane vouches for these, not your key)` : ""}\n`,
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

				if (unchecked && !opts.json) {
					process.stderr.write(
						`\ntlane verify: INCOMPLETE — ${report.anchors_unverified} anchor record(s) were NOT verified.
The hash chain checked out, but signature and Rekor-anchor verification did not run,
so a forged anchor would not have been detected. Re-run with the trusted key:

  tlane verify <ledger> --tenant-pubkey <base64>

Get it out-of-band from Settings \u2192 Audit signing key, or GET /v1/audit/pubkey.
`,
					);
				}

				process.exit(status === "PASS" ? 0 : 1);
			},
		);
}
