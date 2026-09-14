import fs from "node:fs";
import path from "node:path";
import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * FT-04 — R2 outage: SUPERSEDED 2026-09-12 (B-390).
 *
 * The scenario this eval guarded — "Cloudflare R2 unreachable, ingest degrades
 * to ClickHouse-only" — has no subject any more: the R2 cold tier
 * (`crates/ingest/src/r2_batcher.rs`, 901 lines) was DELETED in B-390 because it
 * had ZERO producers; nothing ever wrote to it, so an "R2 outage" could never
 * have degraded anything. Spans are ClickHouse-only, always.
 *
 * What replaced it as the fault-tolerance property of the ingest process:
 * `crates/ingest/src/supervisor.rs` — the NATS consumer (and the auxiliary
 * tasks) are SUPERVISED, so a consumer whose stream ends is restarted rather
 * than left as a live process consuming nothing (the failure B-390 named).
 * The structural assertions below pin the deletion (a reader learns it from
 * the tree) and the supervisor's contract; the supervisor's behaviour is
 * proven by its own Rust tests, named here so a rename fails this eval.
 */

const INGEST_SRC = path.resolve(__dirname, "../../crates/ingest/src");

describe("FT-04: R2 tier deleted — ingest is ClickHouse-only and SUPERVISED (B-390)", () => {
	it("r2_batcher.rs no longer exists, and the ingest doc says why", () => {
		expect(fs.existsSync(path.join(INGEST_SRC, "r2_batcher.rs"))).toBe(false);
		const doc = fs.readFileSync(path.resolve(INGEST_SRC, "../CLAUDE.md"), "utf8");
		expect(doc).toContain("B-390");
	});

	it("the ingest is the sole span writer, into ClickHouse only", () => {
		const writer = fs.readFileSync(path.join(INGEST_SRC, "clickhouse_writer.rs"), "utf8");
		expect(writer).toContain('insert("tracelane.spans")');
		const main = fs.readFileSync(path.join(INGEST_SRC, "main.rs"), "utf8");
		expect(main).not.toContain("r2_batcher");
		expect(main).not.toContain("TRACELANE_R2_");
	});

	it("the consumer and auxiliary tasks are supervised (restart, not silent death)", () => {
		const sup = fs.readFileSync(path.join(INGEST_SRC, "supervisor.rs"), "utf8");
		expect(sup).toContain("pub async fn supervise");
		// Its own proofs, by name — a rename fails here rather than silently.
		expect(sup).toContain("restarts_twice_then_stops_on_manual_shutdown");
		expect(sup).toContain("ok_before_shutdown_is_restarted");
		expect(sup).toContain("ok_after_shutdown_is_not_restarted");
		const main = fs.readFileSync(path.join(INGEST_SRC, "main.rs"), "utf8");
		expect(main).toContain("supervise(");
	});
});
