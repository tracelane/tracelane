import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * GC-002 — Provider registry: native adapters + OpenAI-compatible providers
 *
 * Verifies that ProviderRegistry in crates/gateway/src/providers/mod.rs
 * routes 30+ providers (6 native adapters + any OpenAI-compatible endpoint).
 * This structural test checks the core native adapter files and a
 * representative set of OpenAI-compatible providers:
 *   Native adapters (own source file):
 *     1. anthropic  → providers/anthropic.rs
 *     2. openai     → providers/openai.rs
 *     3. google     → providers/google.rs (Gemini)
 *     4. bedrock    → providers/bedrock.rs
 *   OpenAI-compatible (reuse openai.rs via OpenAiProvider::compatible()):
 *     5. together   → registry field, OpenAI-compatible
 *     6. fireworks  → registry field, OpenAI-compatible
 *     7. groq       → registry field, OpenAI-compatible
 *     8. openrouter → registry field, OpenAI-compatible
 *
 * Structural: check source file existence and registry field mentions.
 * Integration: HTTP routing correctness skipped until Week 8.
 */
describe("GC-002: Provider registry — native + OpenAI-compatible providers", () => {
  it("4 native provider adapter files exist", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const providersDir = path.resolve(
      __dirname,
      "../../crates/gateway/src/providers"
    );

    const nativeAdapters = ["anthropic.rs", "openai.rs", "google.rs", "bedrock.rs"];
    for (const file of nativeAdapters) {
      const p = path.join(providersDir, file);
      expect(fs.existsSync(p), `Missing adapter: ${file}`).toBe(true);
    }
  });

  it("ProviderRegistry struct has fields for the wired providers", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
      "utf8"
    );

    const allProviders = ["anthropic", "openai", "google", "bedrock", "together", "fireworks", "groq", "openrouter"];
    for (const provider of allProviders) {
      expect(src, `Registry missing field: ${provider}`).toContain(provider);
    }
  });

  it("OpenAI-compatible providers use OpenAiProvider::compatible()", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
      "utf8"
    );
    expect(src).toContain("compatible");
    // Together, Fireworks, Groq, OpenRouter all use OpenAI-compatible endpoints
    expect(src).toContain("together.xyz");
    expect(src).toContain("fireworks.ai");
    expect(src).toContain("groq.com");
    expect(src).toContain("openrouter.ai");
  });

  it("ProviderRegistry::new() constructs all providers", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
      "utf8"
    );
    expect(src).toContain("fn new");
    expect(src).toContain("AnthropicProvider::new");
    expect(src).toContain("OpenAiProvider");
    expect(src).toContain("GoogleProvider::new");
    expect(src).toContain("BedrockProvider::new");
  });

  it("MockProvider exists for eval/test use (no real network calls)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
      "utf8"
    );
    expect(src).toContain("MockProvider");
  });

  it.skip("provider routing: POST /v1/chat/completions with x-provider header routes correctly (Week 8)", async () => {
    // Full: send request with x-tracelane-provider: groq header
    // Assert gateway forwards to Groq endpoint with correct auth
  });
});
