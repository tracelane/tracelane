import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * GC-001 — Provider adapter: Anthropic SSE streaming correctness
 *
 * Verifies that the Anthropic provider adapter in crates/gateway/src/providers/
 * correctly implements SSE streaming (Server-Sent Events) per the Anthropic
 * Messages API spec. Key invariants:
 *
 * 1. Content-Type: text/event-stream on streaming responses
 * 2. event: content_block_delta events carry delta.text
 * 3. event: message_stop signals end of stream
 * 4. cache_control headers are forwarded (prompt caching support)
 * 5. extended_thinking blocks are captured in span attributes
 *
 * Structural: verify the adapter source exists and documents SSE handling.
 * Integration: skipped until mock-provider infra is live (Week 8).
 */
describe("GC-001: Anthropic SSE streaming correctness", () => {
  it("Anthropic provider adapter module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const adapters = [
      "../../crates/gateway/src/providers/anthropic.rs",
      "../../crates/gateway/src/providers/mod.rs",
    ];
    for (const rel of adapters) {
      const p = path.resolve(__dirname, rel);
      expect(fs.existsSync(p)).toBe(true);
    }
  });

  it("provider mod defines ProviderAdapter trait", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
      "utf8"
    );
    expect(src).toContain("ProviderAdapter");
    expect(src).toContain("ProviderEvent");
  });

  it("ProviderEvent includes StreamChunk variant", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
      "utf8"
    );
    expect(src).toContain("StreamChunk");
  });

  it("Anthropic adapter handles cache_control (prompt caching)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/anthropic.rs"),
      "utf8"
    );
    expect(src).toContain("cache_control");
  });

  it("Anthropic adapter handles extended thinking", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/anthropic.rs"),
      "utf8"
    );
    expect(src).toContain("extended_thinking");
  });

  it.skip("Anthropic SSE integration: stream delivers content_block_delta events (Week 8)", async () => {
    // Full: spawn gateway with mock Anthropic SSE server
    // Assert event sequence: message_start → content_block_start →
    //   content_block_delta (×N) → content_block_stop → message_delta → message_stop
    // Assert span has tracelane.provider=anthropic, tracelane.model=claude-*
  });
});
