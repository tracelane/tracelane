import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O4 — DuckDB embedded: no 4-service self-host requirement
 *
 * Competitor behavior: Langfuse self-host requires ClickHouse + Postgres +
 * Redis + the app server — 4 services, Docker Compose with 8+ containers.
 * Most teams don't have Kubernetes; the self-host complexity is a blocker.
 *
 * Pain: "Works in cloud, dies on prem." Teams that need on-premise data
 * residency (HIPAA, SOC 2, EU data) face weeks of infra work to self-host
 * an observability tool. It shouldn't be this hard.
 *
 * Tracelane fix: Tracelane Lite embeds DuckDB as the storage backend.
 * Single binary, zero external dependencies, sub-second trace lag (PP-P2).
 * Upgrade path: when you need ClickHouse scale, swap the config key.
 *
 * Eval design:
 * - Assert the codebase has a DuckDB storage backend path
 * - Assert Tracelane Lite can start with TRACELANE_STORAGE=duckdb
 * - Assert query latency <1s for 10K spans in DuckDB mode (PP-P2 companion)
 *
 */
describe("PP-O4: DuckDB embedded — no 4-service self-host", () => {
	// ── FINDING 2026-08-12, recorded rather than tested around ───────────────
	// THIS EVAL COVERED A FEATURE THAT DOES NOT EXIST. It asserted a local array
	// containing "duckdb" and an object claiming `externalServices: 0`, and was
	// green for its whole life. `grep -rn duckdb crates/` returns ZERO hits —
	// there is no DuckDB backend, no `TRACELANE_STORAGE` switch, and no
	// single-binary mode. ClickHouse is the only span store.
	//
	// The founder's rule applies: if an eval turns out to cover a feature that
	// does not exist, that is the finding — say so, do not write a test for it.
	// So both cases are SKIPPED with the reason in the title, and the suite
	// summary now reports them as SKIPPED instead of counting them as coverage.
	// Un-skip them the day a DuckDB backend exists, not before.
	it.skip("TRACELANE_STORAGE=duckdb env var is a documented option [NOT BUILT — zero duckdb hits in crates/]", () => {
		// Architectural assertion: DuckDB backend exists
		// Full check: grep crates/ingest/src for StorageBackend::DuckDb
		const storageBackends = ["clickhouse", "duckdb"];
		expect(storageBackends).toContain("duckdb");
	});

	it.skip("single-binary mode requires no external services [NOT BUILT — no single-binary mode exists]", () => {
		// Tracelane Lite: gateway + ingest + DuckDB in one process
		// No NATS, no ClickHouse, no Redis required
		const liteRequirements = {
			externalServices: 0,
			storageEngine: "duckdb",
		};
		expect(liteRequirements.externalServices).toBe(0);
	});

	// Behavioral half: real DuckDB-backed ingest — write 10K spans, query
	// trace_summaries, measure latency. Not yet wired; skip honestly rather
	// than asserting a hardcoded 50ms constant.
	it.skip("DuckDB query latency <1s for 10K spans — requires live DuckDB-backed ingest run", async () => {
		// TODO: start DuckDB-backed ingest, write 10K spans, time the query.
		expect(true).toBe(true);
	});
});
