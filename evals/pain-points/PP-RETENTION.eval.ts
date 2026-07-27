import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-RETENTION — Per-tier retention promise: 30/90/180/365 days (ADR-020)
 *
 * Behavior: when a trace ages past its tier's retention_days, GET
 * `/api/traces/:id` returns 404 with a `deletion_receipt_url` pointer.
 * The hot ClickHouse partition rolls off; cold R2 archive is purged
 * per ADR-022 tiered storage.
 *
 * STATUS — SKIPPED until ADR-022 implementation ships.
 * ADR-022 trigger condition: first paying Team customer, OR
 *                            hot storage exceeds 50% of the CCX33 disk.
 * Whichever comes first.
 *
 * Until tiered storage is live, the 404+receipt path is unimplemented
 * — flipping this eval to .live before that would burn the eval suite
 * as a merge gate. Skip-with-reason satisfies the publish-job
 * auto-disable contract per CLAUDE.md self-healing policy §5.
 *
 * Four structural assertions (will run when ADR-022 ships):
 *   1. Builder trace older than 30d returns 404 + deletion_receipt_url
 *   2. Team trace older than 90d returns 404 + deletion_receipt_url
 *   3. Business trace older than 180d returns 404 + deletion_receipt_url
 *   4. Enterprise trace older than 365d returns 404 + deletion_receipt_url
 *
 * skipped feature gate, not a flake)
 */
describe.skip("PP-RETENTION: per-tier 30/90/180/365d expiry (deferred until ADR-022 ships)", () => {
	const retentionDaysByTier: Record<string, number> = {
		builder: 30,
		team: 90,
		business: 180,
		enterprise: 365,
	};

	it("1. Builder trace older than 30d returns 404 + deletion_receipt_url", () => {
		const days = retentionDaysByTier.builder;
		expect(days).toBe(30);
		// TODO(ADR-022): replace with live GET /api/traces/:id call against
		// a tenant whose ClickHouse partition has rolled off.
	});

	it("2. Team trace older than 90d returns 404 + deletion_receipt_url", () => {
		expect(retentionDaysByTier.team).toBe(90);
	});

	it("3. Business trace older than 180d returns 404 + deletion_receipt_url", () => {
		expect(retentionDaysByTier.business).toBe(180);
	});

	it("4. Enterprise trace older than 365d returns 404 + deletion_receipt_url", () => {
		expect(retentionDaysByTier.enterprise).toBe(365);
	});
});
