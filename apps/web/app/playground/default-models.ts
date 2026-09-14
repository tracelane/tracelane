/**
 * The playground's model dropdown is built from the tenant's CONNECTED
 * provider keys (`GET /v1/byok/provider-keys`), never a hardcoded catalogue —
 * a provider with no key cannot be run against anyway. What this map supplies
 * is the DEFAULT model id to pre-fill for a connected provider, so the form
 * has a value the moment a key is selected rather than an empty text box.
 *
 * Anchored to the gateway's own routing table, not re-guessed: every pair here
 * is one row of `PROVIDER_MODELS` in
 * `crates/gateway/src/providers/mod.rs:858-892`, the self-validating list the
 * gateway's own tests assert routes to its OWN provider. If that list adds or
 * renames a default, this one is the copy that goes stale — same class as any
 * other code-to-copy anchor (CLAUDE.md §16).
 *
 * A connected provider absent from this map (there are ~169 in the full BYOK
 * catalog, `components/settings/provider-catalog.generated.ts`, most of them
 * OpenAI-compatible resellers with no single canonical model id) falls back to
 * the provider id itself — it may 400 `unroutable_model`, which is itself a
 * proven, honest path (spec §7 proof 3), not a silent failure.
 */
export const DEFAULT_MODEL_BY_PROVIDER: Readonly<Record<string, string>> = {
	anthropic: "claude-sonnet-4-6",
	openai: "gpt-4o",
	google: "gemini-2.5-flash",
	vertex: "vertex/gemini-2.5-pro",
	bedrock: "bedrock/nova-pro",
	azure: "azure/gpt-4o",
	cohere: "command-r-plus",
	mistral: "mistral-large-latest",
	perplexity: "sonar-pro",
	deepseek: "deepseek-chat",
	xai: "grok-2",
	nvidia: "nvidia/llama-3.1-70b",
	cerebras: "cerebras/llama-3.3-70b",
	sambanova: "sambanova/Meta-Llama-3.3-70B",
	lepton: "lepton/llama3-70b",
	lambda: "lambda/llama-3.3-70b",
	novita: "novita/llama-3.3-70b",
	ai21: "jamba-1.5-large",
	hyperbolic: "hyperbolic/llama-3.3-70b",
	deepinfra: "deepinfra/llama-3.3-70b",
	cloudflare: "@cf/meta/llama-3.1-8b",
	ollama: "ollama/llama3.3",
	baseten: "baseten/llama-3.3-70b",
	huggingface: "hf/meta-llama/Llama-3.3-70B",
	anyscale: "anyscale/llama-3.3-70b",
	modal: "modal/llama-3.3-70b",
	predibase: "predibase/llama-3-3-70b",
	moonshot: "moonshot/kimi-k2",
	upstage: "solar-pro",
	yi: "yi-large",
	"aleph-alpha": "luminous-supreme",
	groq: "llama-3.3-70b-versatile",
	together: "together/meta-llama/Llama-3.3-70B",
	fireworks: "fireworks/llama-v3p3-70b",
	openrouter: "openrouter/meta-llama/llama-3.3-70b",
};

/** The default model for a connected provider id, or the id itself if unmapped. */
export function defaultModelFor(providerId: string): string {
	return DEFAULT_MODEL_BY_PROVIDER[providerId] ?? providerId;
}
