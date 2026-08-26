import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * GC-002 — Provider registry: native adapters + OpenAI-compatible providers
 *
 * Verifies that ProviderRegistry in crates/gateway/src/providers/mod.rs routes
 * 150+ providers: the six native adapters plus every row of the catalog at
 * crates/gateway/providers.tsv.
 *
 * WHY SIX IS THE NUMBER. A native adapter is one whose wire format is NOT
 * OpenAI's, so it needs its own Rust module and its own ProviderRegistry field:
 *     1. anthropic → providers/anthropic.rs
 *     2. google    → providers/google.rs   (Gemini, AI Studio)
 *     3. vertex    → providers/vertex.rs   (service-account OAuth, not API keys)
 *     4. bedrock   → providers/bedrock.rs
 *     5. azure     → providers/azure.rs
 *     6. cohere    → providers/cohere.rs
 *
 * This count read 6 before GWY-42 and reads 6 after it, but NOT for the same
 * reason, which is why it is spelled out here rather than trusted:
 *   - It was 7 in the code (openai was a native field too) while this file said
 *     4 and omitted vertex, azure and cohere. The assertion was simply stale.
 *   - GWY-42 moved `openai` into the catalog — it was always an OpenAiProvider,
 *     so a dedicated field only made it look like a different kind of thing.
 *     Nothing was dropped; 7 - 1 = 6.
 * `scripts/ci/check-provider-count.py` derives this from ProviderRegistry's
 * adapter fields, so a stale number here now fails a guard instead of rotting.
 *
 * OpenAI-compatible providers are DATA, not code: they live in providers.tsv
 * and are asserted against that file, not against mod.rs. Before GWY-42 this
 * suite grepped mod.rs for "together.xyz" / "fireworks.ai" / "openrouter.ai";
 * those base URLs moved to the catalog and the assertion went red.
 *
 * Structural: check source file existence, registry fields and catalog rows.
 * Integration: HTTP routing correctness skipped until Week 8.
 */
describe("GC-002: Provider registry — native + OpenAI-compatible providers", () => {
	it("6 native provider adapter files exist", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const providersDir = path.resolve(
			__dirname,
			"../../crates/gateway/src/providers",
		);

		// The six non-OpenAI wire formats. `openai.rs` is deliberately absent:
		// it is the catalog's shared adapter, not a native one.
		const nativeAdapters = [
			"anthropic.rs",
			"google.rs",
			"vertex.rs",
			"bedrock.rs",
			"azure.rs",
			"cohere.rs",
		];
		for (const file of nativeAdapters) {
			const p = path.join(providersDir, file);
			expect(fs.existsSync(p), `Missing adapter: ${file}`).toBe(true);
		}
	});

	it("ProviderRegistry struct has a TYPED field per native adapter", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const src = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
			"utf8",
		);

		// Assert the FIELD DECLARATION, not the bare provider name. A substring
		// like "bedrock" also matches a comment or a test, so the loose form
		// stayed green through GWY-42 while telling us nothing.
		const nativeFields: Array<[string, string]> = [
			["anthropic", "AnthropicProvider"],
			["google", "GoogleProvider"],
			["vertex", "VertexProvider"],
			["bedrock", "BedrockProvider"],
			["azure", "AzureOpenAiProvider"],
			["cohere", "CohereProvider"],
		];
		for (const [field, ty] of nativeFields) {
			expect(src, `Registry missing native field: ${field}`).toContain(
				`pub ${field}: ${ty},`,
			);
		}

		// Everything else is one map keyed by catalog id — not 29 struct fields.
		expect(src, "Registry missing the catalog-backed compat map").toContain(
			"compat: std::collections::HashMap<&'static str, OpenAiProvider>",
		);
	});

	it("OpenAI-compatible providers live in providers.tsv, not in mod.rs", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const tsv = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/providers.tsv"),
			"utf8",
		);

		const rows = tsv
			.split("\n")
			.filter((l) => l && !l.startsWith("#") && !l.startsWith("id\t"));

		// The catalog is the reason the gateway routes 150+ providers. A handful
		// of rows would mean the TSV parsed but did not load.
		expect(rows.length >= 100, `catalog has only ${rows.length} rows`).toBe(
			true,
		);

		// Spot-check the majors was about, by BASE URL — these four routed
		// but could not accept a BYOK key. Their base URLs moved from mod.rs to
		// here in GWY-42; asserting the id alone would not prove the row is wired.
		const byId = new Map(rows.map((l) => [l.split("\t")[0], l.split("\t")]));
		const majors: Array<[string, string]> = [
			["together", "together.xyz"],
			["fireworks", "fireworks.ai"],
			["groq", "groq.com"],
			["openrouter", "openrouter.ai"],
			["openai", "api.openai.com"],
		];
		for (const [id, host] of majors) {
			const row = byId.get(id);
			expect(row !== undefined, `catalog missing row: ${id}`).toBe(true);
			expect(row?.[2] ?? "", `${id} base_url is not ${host}`).toContain(host);
		}
	});

	it("ProviderRegistry::new() constructs all providers", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const src = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
			"utf8",
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
			"utf8",
		);
		expect(src).toContain("MockProvider");
	});

	it.skip("provider routing: POST /v1/chat/completions with x-provider header routes correctly (Week 8)", async () => {
		// Full: send request with x-tracelane-provider: groq header
		// Assert gateway forwards to Groq endpoint with correct auth
	});
});
