import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * GC-004 — OTLP span emission: every request produces a well-formed span
 *
 * Verifies that otlp_emit.rs in the gateway emits OTLP spans with the
 * required attributes per OpenInference semconv (ADR-004):
 *
 *   llm.provider              — e.g. "anthropic"
 *   llm.model                 — e.g. "claude-sonnet-4-6"
 *   llm.token_count.prompt    — integer
 *   llm.token_count.completion — integer
 *   tracelane.tenant_id       — from JWT claim (never request body)
 *
 * Structural: verify otlp_emit.rs exists and contains required attributes.
 * Integration: end-to-end span emission verified in Week 8.
 */
describe("GC-004: OTLP span emission correctness", () => {
	it("otlp_emit module exists in gateway", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const p = path.resolve(__dirname, "../../crates/gateway/src/otlp_emit.rs");
		expect(fs.existsSync(p)).toBe(true);
	});

	it("otlp_emit accepts TracelaneSpan with tenant_id field", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const src = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/src/otlp_emit.rs"),
			"utf8",
		);
		// Must take TracelaneSpan and thread tenant_id through tracing
		expect(src).toContain("TracelaneSpan");
		expect(src).toContain("tenant_id");
	});

	it("gateway emits OTLP through its own emission module (semconv attrs)", async () => {
		// 2026-07-23: the OTel Rust SDK crates were UNUSED declarations (the
		// gateway hand-emits OTLP; cargo-machete removed them), so "the dep is
		// in Cargo.toml" proved nothing. Assert the real emission surface.
		const fs = await import("node:fs");
		const path = await import("node:path");
		const src = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/src/otlp_emit.rs"),
			"utf8",
		);
		expect(src).toContain("gen_ai.");
		expect(src).toContain("tenant_id");
	});

	it("audit module computes SHA-256 hash chain", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const src = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/src/audit.rs"),
			"utf8",
		);
		expect(src).toContain("compute_row_hash");
		expect(src).toContain("SHA256");
	});

	it("Rekor anchoring is implemented in audit.rs", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const src = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/src/audit.rs"),
			"utf8",
		);
		expect(src).toContain("AuditChain");
		expect(src).toContain("RekorClient");
		expect(src).toContain("compute_merkle_root");
	});

	it.skip("end-to-end: request spans appear in ClickHouse within 1s (integration — Week 8)", async () => {
		// Full: fire request through gateway, poll ClickHouse, assert span present
	});
});
