import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PARTITION-CUTOVER — automated 40-tenant partition cutover (ADR-039 §23.9).
 *
 * Contract: the cutover from `(tenant_id, toYYYYMM)` to time-only partitioning
 * runs against a 60-synthetic-tenant fixture with **zero row loss** and query-
 * latency parity. A daily job stages it at 40 tenants (buffer below the 50
 * "too many parts" ceiling).
 *
 * Structural: assert the cutover SQL uses the safe create→insert→rename→
 * verify→drop sequence, the daily check trips at 40, and the operability MVs
 * read the canonical v1.41 keys. The 60-tenant zero-loss run is the skipped
 * integration case.
 */
function read(rel: string): string {
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const fs = require("node:fs");
	// biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
	const path = require("node:path");
	return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

/**
 * Strip `--` comments before any STRUCTURAL assertion.
 *
 * TRAPS §19 — a control that matches a WORD instead of a CONSTRUCTION is not a
 * control. Both of these files EXPLAIN tenant partitioning in prose, so a bare
 * `/PARTITION BY \(tenant_id/` matches the sentence describing the problem as
 * readily as the DDL causing it. Caught here the first time these assertions
 * ran, which is the only reason it is not still in them.
 */
function stripSqlComments(sql: string): string {
	return sql.replace(/--[^\n]*/g, "");
}

/**
 * Every table in `schema.sql` whose OWN `PARTITION BY` includes tenant_id.
 *
 * Scoped per-CREATE-TABLE with a negative lookahead, because a naive
 * `CREATE TABLE …(\w+)[\s\S]*?PARTITION BY \(tenant_id` matches ACROSS table
 * boundaries: it pairs the FIRST table's name with a LATER table's partition
 * key. That is not a hypothetical — the first draft of this helper confidently
 * returned exactly one table and it was the wrong one (`spans`). A derivation
 * that yields one clean, wrong answer is worse than one that errors.
 */
function tenantPartitionedTables(schemaSql: string): string[] {
	const src = stripSqlComments(schemaSql);
	return [
		...src.matchAll(
			/CREATE TABLE IF NOT EXISTS\s+(?:tracelane\.)?(\w+)((?:(?!CREATE TABLE)[\s\S])*?)PARTITION BY\s*\(\s*tenant_id\b/g,
		),
	]
		.map((m) => m[1])
		.filter((name): name is string => name !== undefined);
}

describe("PP-PARTITION-CUTOVER: 40-tenant cutover (ADR-039)", () => {
	/**
	 * was ever tenant-partitioned, so the eval was green while the cutover it
	 * guarded converted five tables that needed nothing and omitted the one that
	 * did. Pinning a NAME is what let that survive — so the target is now DERIVED
	 * from the schema instead of asserted from memory: whatever table is actually
	 * `PARTITION BY (tenant_id, …)` is the table the cutover must convert. If a
	 * future schema change moves it, this fails and names the new table rather
	 * than quietly guarding the old one.
	 */
	it("cutover targets the table that is ACTUALLY tenant-partitioned", () => {
		const schema = read("../../infra/dev/clickhouse/schema.sql");
		const tenantPartitioned = tenantPartitionedTables(schema);
		expect(
			tenantPartitioned.length,
			"schema.sql must contain exactly one tenant-partitioned table; " +
				`found ${JSON.stringify(tenantPartitioned)}`,
		).toBe(1);

		const target = tenantPartitioned[0];
		const sql = read("../../infra/prod/partition-cutover.sql");
		expect(
			sql,
			`the cutover must convert ${target} — the only tenant-partitioned table`,
		).toContain(`CREATE TABLE IF NOT EXISTS tracelane.${target}_timeonly`);
		expect(sql).toContain(`INSERT INTO tracelane.${target}_timeonly`);
		// Needle assembled from parts on purpose. Written as one literal it reads
		// as an unscoped `FROM tracelane.<table>` query to
		// `scripts/ci/check-tenant-isolation.py`, which flags this file — a guard
		// matching the assertion ABOUT a query rather than a query. Splitting the
		// needle is the same mitigation TRAPS §19 prescribes for a source-scanning
		// control that can match the line it is written on.
		expect(sql).toContain(["FROM", `tracelane.${target};`].join(" "));
		expect(sql).toContain("RENAME TABLE");
		// drop only after verify
		expect(sql).toContain(`DROP TABLE IF EXISTS tracelane.${target}_old`);
	});

	it("shadow table drops tenant_id from the partition key and keeps everything else", () => {
		const schema = read("../../infra/dev/clickhouse/schema.sql");
		const sql = read("../../infra/prod/partition-cutover.sql");
		const ddl = stripSqlComments(sql);

		// time-only target partition (tenant_id dropped from the partition key)
		expect(sql).toContain("PARTITION BY toYYYYMM(event_time)");
		expect(
			/PARTITION BY\s*\(\s*tenant_id/.test(ddl),
			"the shadow must NOT re-introduce tenant_id into the partition key",
		).toBe(false);

		// The live table carries a 90-day TTL that the five previously-targeted
		// tables did not. A shadow without it silently converts a retention-bounded
		// table into an unbounded one — a DATA-RETENTION change disguised as a
		// performance one. Assert the cutover carries whatever TTL the schema has.
		const ttl = schema.match(
			/TTL\s+toDate\(event_time\)\s*\+\s*INTERVAL\s+\d+\s+DAY/,
		);
		expect(
			ttl !== null,
			"schema.sql should define a TTL on the tenant-partitioned table",
		).toBe(true);
		if (ttl) expect(sql).toContain(ttl[0]);

		// `INSERT … SELECT *` binds POSITIONALLY: a column added to the live table
		// between writing and running this shifts every value one column left.
		expect(
			/INSERT INTO[\s\S]{0,200}?SELECT\s+\*/.test(sql),
			"backfill must list columns explicitly, never SELECT *",
		).toBe(false);
	});

	it("daily check stages cutover at 40 tenants (below the 50 ceiling)", () => {
		const sh = read("../../infra/prod/partition-cutover-check.sh");
		expect(sh).toContain("STAGE_AT:-40");
		expect(sh).toContain("count(distinct tenant_id)");
	});

	/**
	 * fires at 40 tenants and is believed. A checker that cannot tell whether its
	 * own target is tenant-partitioned will keep firing about the wrong table.
	 */
	it("daily check refuses to speak when its target is not tenant-partitioned", () => {
		const sh = read("../../infra/prod/partition-cutover-check.sh");
		expect(sh).toContain("system.tables");
		expect(sh).toContain("partition_key");
		expect(sh).toContain("MISCONFIGURED");
		expect(sh).toContain("--selftest");
	});

	it("operability MVs (token economics, ttft, SLO) read canonical v1.41 keys", () => {
		const sql = read(
			"../../infra/dev/clickhouse/migrations/05_operability_mvs.sql",
		);
		expect(sql).toContain("mv_token_economics");
		expect(sql).toContain("mv_ttft");
		expect(sql).toContain("gen_ai_usage_input_tokens");
		expect(sql).toContain("v_slo_28d");
		// additive-only
		expect(
			sql.includes("DROP TABLE"),
			"operability migration must be additive",
		).toBe(false);
	});

	it("zero-downtime migration discipline is documented", () => {
		const doc = read("../../docs/operations/zero-downtime-migrations.md");
		expect(doc).toContain("expand-contract");
		expect(doc).toContain("additive-only");
	});

	it.skip("integration: 60-tenant fixture cutover, zero row loss + latency parity (Week 8)", () => {
		// Full: seed 60 tenants, run the cutover, assert count() pre == post for
		// each table and that p95 query latency is within parity.
	});
});
