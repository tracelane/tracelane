/**
 * E2E-only audit-ledger fixture seam — hero launch-gate coverage (ADR-062).
 *
 * Gated on the dev/test-only e2e auth bypass (`e2eAuthEnabled`) — it returns
 * `null` in a production build and THROWS if a prod build ever carries the
 * bypass flag (fail-closed, inherited from `lib/e2e-auth.ts`). This lets the
 * Playwright launch gate drive the REAL in-browser verifier over a REAL anchored
 * ledger (verified GREEN + public Rekor anchor + logIndex) and over a tampered
 * copy (loud-red broken chain) WITHOUT a live gateway or a seeded Neon — the
 * "founder must wire seed data" gap that kept the hero audit specs skipping.
 *
 * The fixture is a committed conformance vector
 * (`e2e/fixtures/audit-fixture-data.ts`, generated from
 * `evals/audit-ledger/anchored.v1.ndjson`). It is **dynamically imported** so it
 * is code-split out of the production bundle and never loaded at runtime in prod.
 */

import { e2eAuthEnabled } from "@/lib/e2e-auth";

export type AuditFixture = { ndjson: string; tenantPubkeyB64: string };

/** Mutate one non-anchor row's payload so its recomputed row_hash mismatches. */
function tamper(ndjson: string): string {
	const lines = ndjson.split("\n").filter(Boolean);
	const i = lines.findIndex((l) => JSON.parse(l).type !== "anchor");
	const target = i >= 0 ? lines[i] : undefined;
	if (!target) return `${lines.join("\n")}\n`;
	const row = JSON.parse(target);
	const payload =
		typeof row.payload === "string" ? row.payload : JSON.stringify(row.payload);
	row.payload = `${payload}_E2E_TAMPERED`;
	lines[i] = JSON.stringify(row);
	return `${lines.join("\n")}\n`;
}

/**
 * The requested audit fixture, or `null` when the e2e bypass is off (i.e. always
 * `null` in production). `variant`: `"anchored"` (default — verifies GREEN with a
 * resolved public anchor) or `"tampered"` (verifies RED — broken chain).
 */
export async function e2eAuditFixture(
	variant?: string,
): Promise<AuditFixture | null> {
	if (!e2eAuthEnabled()) return null;
	const { ANCHORED_NDJSON, TRUSTED_PUBKEY_B64 } = await import(
		"@/e2e/fixtures/audit-fixture-data"
	);
	const ndjson =
		variant === "tampered" ? tamper(ANCHORED_NDJSON) : ANCHORED_NDJSON;
	return { ndjson, tenantPubkeyB64: TRUSTED_PUBKEY_B64 };
}
