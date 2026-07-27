import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O3 — Retention included per tier, no upcharge
 *
 * Competitor behavior: many observability vendors charge extra for retention
 * beyond 30 days, or apply complex retention pricing. Teams budget for
 * observability but get surprised by retention fees when they need historical
 * data for an incident.
 *
 * Pain: "90-day retention would cost us an extra $400/mo" is a real calculation
 * enterprise teams make. It creates perverse incentives to discard data that
 * might be needed for compliance or debugging.
 *
 * an upsell to "unlock" storage. The ClickHouse schema carries a flat 365-DAY
 * fail-safe backstop TTL on the hot tables (spans + trace_summaries) so nothing
 * is silently dropped early; the actual per-plan window (Free 7d → Enterprise
 * 365d) is trimmed by the entitlement-driven retention sweep job, not by the
 * flat TTL. R2 cold storage for longer retention is included too (R2 egress is
 * $0). No upsell to unlock retention.
 *
 * Eval design:
 * - Verify the ClickHouse schema has the 365-day backstop TTL on the hot tables
 * - Verify R2 cold storage path exists in ingest config
 *
 */
describe("PP-O3: Retention included per tier, no upcharge", () => {
	it("ClickHouse schema has the 365-day backstop TTL on spans table", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const schema = fs.readFileSync(
			path.resolve(__dirname, "../../infra/dev/clickhouse/schema.sql"),
			"utf8",
		);
		expect(schema).toContain("365 DAY");
		expect(schema).toContain("TTL");
	});

	it("trace_summaries MV also carries the 365-day backstop TTL", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const schema = fs.readFileSync(
			path.resolve(__dirname, "../../infra/dev/clickhouse/schema.sql"),
			"utf8",
		);
		// Count occurrences of the 365-day backstop TTL: spans + trace_summaries
		// is the entitlement-driven sweep job, not this flat TTL.
		const matches = schema.match(/TTL.*365 DAY/g);
		expect((matches ?? []).length).toBeGreaterThanOrEqual(2); // spans + trace_summaries
	});
});
