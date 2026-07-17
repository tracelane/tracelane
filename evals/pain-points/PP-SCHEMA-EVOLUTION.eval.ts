import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-SCHEMA-EVOLUTION — OTel GenAI semconv v1.34 → v1.41 dual-emission +
 *
 * Contract: an adapter emitting the legacy v1.34 schema (`gen_ai.system`) and
 * one emitting v1.41 (`gen_ai.provider.name`) must land in IDENTICAL canonical
 * ClickHouse rows — zero data loss. The store is the normalization point: the
 * ingest decoder maps both wire schemas onto the canonical column set.
 *
 * Structural (this file): assert the migration, span model, decoder
 * normalization, and dual-emission switch are all present and wired.
 * Behavioral correctness is proven by Rust unit tests in
 * `crates/ingest/src/otlp_decode.rs` (legacy + v1.41 → identical SpanAttributes).
 * Full live-ClickHouse round-trip is the skipped integration case below.
 */
function read(rel: string): string {
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const fs = require("node:fs");
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const path = require("node:path");
  return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-SCHEMA-EVOLUTION: semconv v1.41 dual-emission + normalization", () => {
  it("span model carries the canonical v1.41 attributes", () => {
    const src = read("../../crates/shared/src/span.rs");
    for (const field of [
      "gen_ai_provider_name",
      "gen_ai_usage_cache_read_input_tokens",
      "gen_ai_usage_cache_creation_input_tokens",
      "gen_ai_usage_reasoning_output_tokens",
      "gen_ai_request_stream",
      "gen_ai_response_time_to_first_chunk",
      "gen_ai_agent_version",
      "gen_ai_conversation_id",
    ]) {
      expect(src.includes(field), `span.rs missing ${field}`).toBe(true);
    }
  });

  it("ingest decoder normalizes legacy gen_ai.system → canonical provider", () => {
    const src = read("../../crates/ingest/src/otlp_decode.rs");
    // legacy key back-fills the canonical column
    expect(src).toContain('"gen_ai.system"');
    expect(src).toContain("gen_ai_provider_name.is_none()");
    // v1.41 keys are decoded
    expect(src).toContain('"gen_ai.usage.cache_read.input_tokens"');
    expect(src).toContain('"gen_ai.usage.reasoning.output_tokens"');
    expect(src).toContain('"gen_ai.conversation.id"');
    // legacy gen_ai.openai.* → openai.* rename
    expect(src).toContain('starts_with("gen_ai.openai.")');
  });

  it("emit path implements OTEL_SEMCONV_STABILITY_OPT_IN dual-emission", () => {
    const src = read("../../crates/gateway/src/otlp_emit.rs");
    expect(src).toContain("OTEL_SEMCONV_STABILITY_OPT_IN");
    expect(src).toContain("gen_ai_latest_experimental");
    // experimental emits provider.name; legacy emits system
    expect(src).toContain('"gen_ai.provider.name"');
    expect(src).toContain('"gen_ai.system"');
    // new v1.41 events
    expect(src).toContain("gen_ai.client.operation.exception");
    expect(src).toContain("gen_ai.evaluation.result");
  });

  it("additive ClickHouse migration adds the canonical v1.41 columns", () => {
    const src = read(
      "../../infra/dev/clickhouse/migrations/04_semconv_v1_41_columns.sql"
    );
    expect(src).toContain("ADD COLUMN IF NOT EXISTS");
    expect(src).toContain("cache_read_input_tokens");
    expect(src).toContain("reasoning_output_tokens");
    expect(src).toContain("time_to_first_chunk_s");
    // additive-only: no destructive DDL
    expect(src.includes("DROP COLUMN"), "migration must be additive-only").toBe(
      false
    );
  });

  it("at least one SDK adapter emits the v1.40 cache-token attribute", () => {
    const src = read(
      "../../packages/sdk-python/tracelane/instrumentations/anthropic.py"
    );
    expect(src).toContain("gen_ai.usage.cache_read.input_tokens");
  });

  it.skip("integration: legacy + v1.41 OTLP land in identical CH rows (live CH — Week 8)", () => {
    // Full: POST a legacy-schema span and a v1.41-schema span to the ingest
    // OTLP receiver, query tracelane.spans, assert canonical columns are equal.
  });
});
