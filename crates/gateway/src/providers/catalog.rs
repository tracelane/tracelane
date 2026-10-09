//! The provider catalog — GWY-42.
//!
//! `../../providers.tsv` is embedded with `include_str!` and parsed once into
//! borrowed `&'static str` slices of that embedded text. Nothing is allocated
//! per provider except the index vectors, and no string is ever copied or
//! leaked: a subslice of a `&'static str` is itself `&'static str`, which is
//! exactly the lifetime every downstream signature already required.
//!
//! **Why a data file and not 163 struct fields.** Adding one OpenAI-compatible
//! provider used to cost ~15 lines of Rust across six files — a struct field,
//! four `match` arms, a dispatch arm, a BYOK allowlist entry — plus ~10 count
//! and claim edits across six more. Every one of those is a place two lists can
//! disagree, and they have: (a model dispatched to Groq while its BYOK
//! key resolved under "anthropic") and ("routed ≠ usable" — providers
//! counted but not storable) are both that shape.
//!
//! ## The resolver, and the two properties it must not break
//!
//! **1. Fail-closed.** An unmatched model returns `None`. There is no
//! default provider and this file must never grow one: a default sends the
//! caller's key for a provider they never named.
//!
//! **2. Today's routing, unchanged.** The hand-written table was an ordered
//! `match`, so `llama-3.1-sonar-*` reached perplexity only because perplexity's
//! arm sat above groq's `llama` arm. Order in a data file is fragile — a sort,
//! a merge, an editor could change it invisibly. So order is *derived*, not
//! written down:
//!
//!   - **namespaced prefixes first** (`groq/`, `@cf/`) — they carry an explicit
//!     provider, so they can never be ambiguous with a bare model name;
//!   - **then bare prefixes, LONGEST FIRST** — so `llama-3.1-sonar` (15 chars,
//!     perplexity) wins over `llama` (5 chars, groq), reproducing the old arm
//!     order from the data itself.
//!
//! `catalog_reproduces_the_legacy_routing_table` pins this against a
//! table of real model strings, and it is the test that makes this refactor
//! safe rather than merely plausible.
//!
//! ## Hot-path cost
//!
//! `provider_id_for_model` is reached at least six times per chat request, and
//! B-256 (a 13× production overhead regression) is open, so this must not be
//! slower than the `match` chain it replaces. Prefixes are bucketed by their
//! **first byte**, so a lookup scans only the handful of prefixes that share the
//! model's first character — typically one to five `starts_with` calls, against
//! up to 36 sequential arms before. Building the index is one-time, at startup.

use std::collections::HashMap;
use std::sync::OnceLock;

/// One OpenAI-compatible provider. Native adapters (Anthropic, Google, Vertex,
/// Bedrock, Azure, Cohere) are deliberately NOT here — their wire format
/// genuinely differs, and generalising them would buy nothing.
#[derive(Debug, Clone)]
pub struct ProviderDef {
    pub id: &'static str,
    // Column 2 of `providers.tsv` (see the header at its top). Parsed to keep
    // this struct a faithful 1:1 mirror of the TSV row shape, but no Rust
    // code reads it today: the dashboard dropdown's display name is
    // generated straight from the TSV by `scripts/ci/build-provider-catalog.py`
    // (its own `label` variable), not from this struct. A test asserts every
    // row's label is non-empty.
    #[allow(dead_code)]
    pub label: &'static str,
    /// Compiled-in default. `base_url()` prefers the env override.
    pub base_url_default: &'static str,
    pub base_url_env: &'static str,
    /// Empty for a provider that needs no key (Ollama is local).
    pub api_key_env: &'static str,
    pub prefixes: Vec<&'static str>,
    /// `OG-01`: column 7 of `providers.tsv`. `true` only for a provider whose
    /// OWN documentation confirms an OpenAI-Responses-compatible
    /// `{base_url}/v1/responses` endpoint — the generator's `RESPONSES_WIRE`
    /// table carries the doc URL for every `true`. `false` (or a row written
    /// before the column existed) means `/v1/responses` TRANSLATES for this
    /// provider instead of relaying, which is the conservative answer: a relay
    /// to a host without the endpoint is a 404 that reads as an outage.
    pub responses_wire: bool,
    /// `OG-06`: column 8 of `providers.tsv` — the non-chat endpoints (`images`,
    /// `images_edits`, `audio_speech`, `audio_transcription`, `moderation`, `rerank`,
    /// `files`, `batch`) the provider's OWN documentation shows at the OpenAI path. The
    /// generator derives it from a doc-URL table; the DEFAULT is none, so an endpoint
    /// is refused `400 unsupported_endpoint` for a provider that was never verified.
    pub capabilities: Vec<&'static str>,
}

impl ProviderDef {
    /// Does the provider's documentation show `capability` at the OpenAI path?
    #[must_use]
    pub fn has_capability(&self, capability: &str) -> bool {
        // `contains` would need `capability: &'static str`; the caller's is not.
        #[allow(clippy::manual_contains)]
        let has = self.capabilities.iter().any(|c| *c == capability);
        has
    }

    /// The base URL to actually dial: `<PROVIDER>_BASE_URL` if set, else the
    /// compiled-in default. Read at construction, not per request.
    #[must_use]
    pub fn base_url(&self) -> String {
        std::env::var(self.base_url_env).unwrap_or_else(|_| self.base_url_default.to_owned())
    }
}

const CATALOG_TSV: &str = include_str!("../../providers.tsv");

struct Catalog {
    providers: Vec<ProviderDef>,
    by_id: HashMap<&'static str, usize>,
    /// `first byte -> [(prefix, provider_id)]`, already in resolution order:
    /// namespaced before bare, longest before shortest.
    buckets: Vec<Vec<(&'static str, &'static str)>>,
}

fn is_namespaced(prefix: &str) -> bool {
    // `@cf/` is Cloudflare's own model namespace; it is unambiguous for the same
    // reason a `provider/` prefix is, so it sorts with them.
    prefix.contains('/') || prefix.starts_with('@')
}

fn parse(tsv: &'static str) -> Catalog {
    let mut providers = Vec::new();
    for line in tsv.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let mut f = line.split('\t');
        let (Some(id), Some(label), Some(base), Some(base_env), Some(key_env), Some(prefixes)) =
            (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            // A short row means the generated file is malformed. Skipping it
            // would drop a provider silently; the catalog is generated and
            // guarded, so a bad row is a bug to surface, not to tolerate.
            panic!("providers.tsv: malformed row (expected 6 tab-separated fields): {line}");
        };
        providers.push(ProviderDef {
            id,
            label,
            base_url_default: base,
            base_url_env: base_env,
            api_key_env: key_env,
            prefixes: prefixes.split(',').filter(|p| !p.is_empty()).collect(),
            // Optional 7th column; absent or anything but `true` is `false`.
            responses_wire: f.next() == Some("true"),
            // Optional 8th column (OG-06); a row written before it has none.
            capabilities: f
                .next()
                .unwrap_or("")
                .split(',')
                .filter(|c| !c.is_empty())
                .collect(),
        });
    }
    assert!(
        !providers.is_empty(),
        "providers.tsv parsed to zero providers — the gateway cannot route anything"
    );

    let by_id = providers
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id, i))
        .collect::<HashMap<_, _>>();

    let mut flat: Vec<(&'static str, &'static str)> = providers
        .iter()
        .flat_map(|p| p.prefixes.iter().map(move |pre| (*pre, p.id)))
        .collect();
    // The whole ordering contract, in one comparator: namespaced first, then
    // longest first. `then_with(id)` only makes the sort total so the build is
    // reproducible; it never decides a real match.
    flat.sort_by(|a, b| {
        is_namespaced(b.0)
            .cmp(&is_namespaced(a.0))
            .then_with(|| b.0.len().cmp(&a.0.len()))
            .then_with(|| a.1.cmp(b.1))
    });

    let mut buckets: Vec<Vec<(&'static str, &'static str)>> = vec![Vec::new(); 256];
    for (pre, id) in flat {
        let Some(&b) = pre.as_bytes().first() else {
            continue;
        };
        buckets[b as usize].push((pre, id));
    }

    Catalog {
        providers,
        by_id,
        buckets,
    }
}

fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| parse(CATALOG_TSV))
}

/// Every OpenAI-compatible provider, in file order.
#[must_use]
pub fn providers() -> &'static [ProviderDef] {
    &catalog().providers
}

/// Look a provider up by its canonical id.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static ProviderDef> {
    let c = catalog();
    c.by_id.get(id).map(|&i| &c.providers[i])
}

/// Resolve a model string to a catalog provider id, or `None`.
///
/// `None` is a real answer and the caller must fail closed on it. This
/// function is deliberately incapable of returning a default.
#[must_use]
pub fn provider_id_for_model(model: &str) -> Option<&'static str> {
    let c = catalog();
    let b = *model.as_bytes().first()? as usize;
    c.buckets[b]
        .iter()
        .find(|(pre, _)| model.starts_with(*pre))
        .map(|(_, id)| *id)
}

/// The API-key env var for a catalog provider. Empty string for keyless
/// providers (Ollama), `None` if the id is not in the catalog at all — the
/// caller must not conflate the two.
#[must_use]
pub fn api_key_env(provider_id: &str) -> Option<&'static str> {
    by_id(provider_id).map(|p| p.api_key_env)
}

/// `OG-01`: does this catalog provider serve the OpenAI Responses wire natively?
/// `false` for every native adapter and for an id the catalog does not carry —
/// the caller then translates, never relays to an endpoint that may not exist.
#[must_use]
pub fn responses_wire(provider_id: &str) -> bool {
    by_id(provider_id).is_some_and(|p| p.responses_wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `OG-06`: the capability column is the ONLY thing that lets a non-chat endpoint
    /// reach a provider, and its default is none.
    #[test]
    fn og06_capabilities_are_doc_derived_and_default_to_none() {
        let openai = by_id("openai").expect("openai");
        for c in [
            "images",
            "images_edits",
            "audio_speech",
            "audio_transcription",
            "moderation",
            "files",
            "batch",
        ] {
            assert!(openai.has_capability(c), "openai {c}");
        }
        // OpenAI publishes no rerank endpoint: never granted by default.
        assert!(!openai.has_capability("rerank"));
        // xAI documents generations but its edit endpoint takes JSON, not OpenAI's multipart.
        let xai = by_id("xai").expect("xai");
        assert!(xai.has_capability("images") && !xai.has_capability("images_edits"));
        assert!(
            by_id("together")
                .expect("together")
                .has_capability("rerank")
        );
        assert!(
            by_id("mistral")
                .expect("mistral")
                .has_capability("moderation")
        );
        // An unverified provider has NOTHING.
        let p = providers();
        let with_any = p.iter().filter(|d| !d.capabilities.is_empty()).count();
        assert!(with_any < 10, "capabilities must stay opt-in per doc URL");
        assert!(by_id("cerebras").is_some_and(|d| d.capabilities.is_empty()));
        assert!(!openai.has_capability("teleport"));
    }

    #[test]
    fn catalog_parses_and_is_large_enough_to_be_the_catalog() {
        let p = providers();
        assert!(
            p.len() >= 100,
            "catalog has {} rows; the whole point of GWY-42 is 100+",
            p.len()
        );
        assert!(by_id("groq").is_some());
        assert!(by_id("definitely-not-a-provider").is_none());
    }

    #[test]
    fn every_row_is_well_formed() {
        for p in providers() {
            assert!(!p.id.is_empty(), "empty id");
            assert!(!p.label.is_empty(), "{}: empty label", p.id);
            assert!(
                p.base_url_default.starts_with("https://")
                    || p.base_url_default.starts_with("http://localhost"),
                "{}: base_url `{}` is neither https nor localhost",
                p.id,
                p.base_url_default
            );
            assert!(
                !p.prefixes.is_empty(),
                "{}: no prefixes — it would be unreachable",
                p.id
            );
        }
    }

    /// `OG-01`: exactly the providers whose own docs confirm a Responses
    /// endpoint relay natively; everything else (and every unknown id)
    /// translates. A row flipped by hand without a doc URL in the generator's
    /// table fails `build-provider-catalog.py --check`; this pins the result.
    #[test]
    fn responses_wire_is_true_only_for_doc_confirmed_providers() {
        for id in ["openai", "xai", "openrouter"] {
            assert!(responses_wire(id), "{id} serves /v1/responses natively");
        }
        for id in [
            "groq",
            "deepseek",
            "anthropic",
            "google",
            "no-such-provider",
        ] {
            assert!(!responses_wire(id), "{id} must translate, not relay");
        }
    }

    #[test]
    fn no_two_providers_claim_the_same_prefix() {
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for p in providers() {
            for pre in &p.prefixes {
                if let Some(other) = seen.insert(pre, p.id) {
                    panic!("prefix `{pre}` claimed by both `{other}` and `{}`", p.id);
                }
            }
        }
    }

    /// THE test that makes this refactor safe. Every one of these pairs was read
    /// off the hand-written `match` arms this catalog replaced. If the catalog
    /// disagrees with even one, live traffic would move to a different provider
    /// — and, because the BYOK key is fetched by provider id, would be sent with
    /// a different tenant credential (the shape).
    #[test]
    fn catalog_reproduces_the_legacy_routing_table() {
        // (model, expected provider) — catalog providers only. The six native
        // adapters are resolved by `ProviderRegistry::provider_id_for_model`,
        // which consults them before this catalog.
        let cases: &[(&str, &str)] = &[
            ("gpt-4o", "openai"),
            ("gpt-5", "openai"),
            ("openai/gpt-4o", "openai"),
            ("o1-preview", "openai"),
            ("o3-mini", "openai"),
            ("text-embedding-3-small", "openai"),
            ("mistral-large-latest", "mistral"),
            ("mixtral-8x7b", "mistral"),
            ("sonar-pro", "perplexity"),
            ("perplexity/sonar", "perplexity"),
            // The ordering case: BOTH of these start with `llama`.
            ("llama-3.1-sonar-small-128k-online", "perplexity"),
            ("llama-3.3-70b-versatile", "groq"),
            ("qwen/qwen3-32b", "groq"),
            ("gemma2-9b-it", "groq"),
            ("deepseek-chat", "deepseek"),
            ("deepseek-reasoner", "deepseek"),
            ("grok-4", "xai"),
            ("xai/grok-3", "xai"),
            ("nvidia/nemotron-4", "nvidia"),
            ("cerebras/llama3.1-8b", "cerebras"),
            ("sambanova/Meta-Llama-3.1-8B", "sambanova"),
            ("lepton/llama3-1-405b", "lepton"),
            ("lambda/hermes-3", "lambda"),
            ("novita/llama-3", "novita"),
            ("ai21/jamba-1.5-large", "ai21"),
            ("jamba-instruct", "ai21"),
            ("j2-ultra", "ai21"),
            ("hyperbolic/llama-3", "hyperbolic"),
            ("deepinfra/llama-3", "deepinfra"),
            ("@cf/meta/llama-3-8b-instruct", "cloudflare"),
            ("cloudflare/llama-3", "cloudflare"),
            ("ollama/llama3", "ollama"),
            ("baseten/llama-3", "baseten"),
            ("hf/meta-llama/Llama-3", "huggingface"),
            ("huggingface/meta-llama/Llama-3", "huggingface"),
            ("anyscale/llama-3", "anyscale"),
            ("modal/llama-3", "modal"),
            ("predibase/llama-3", "predibase"),
            ("moonshot/kimi-k2", "moonshot"),
            ("solar-pro", "upstage"),
            ("upstage/solar-mini", "upstage"),
            ("yi-large", "yi"),
            ("yi/yi-34b", "yi"),
            ("luminous-supreme", "aleph-alpha"),
            ("aleph-alpha/luminous", "aleph-alpha"),
            ("together/meta-llama/Llama-3.3-70B", "together"),
            (
                "fireworks/accounts/fireworks/models/llama-v3p1-70b",
                "fireworks",
            ),
            ("openrouter/openai/gpt-4o", "openrouter"),
        ];
        for (model, want) in cases {
            assert_eq!(
                provider_id_for_model(model),
                Some(*want),
                "model `{model}` must still route to `{want}`"
            );
        }
    }

    #[test]
    fn an_unmatched_model_is_none_never_a_default() {
        for m in [
            "totally-made-up-model",
            "zzz",
            "",
            "  ",
            "/",
            "not-a-provider/some-model",
        ] {
            assert_eq!(
                provider_id_for_model(m),
                None,
                "`{m}` must be unroutable, not defaulted (B-127)"
            );
        }
    }

    #[test]
    fn keyless_and_unknown_are_not_the_same_answer() {
        assert_eq!(api_key_env("ollama"), Some(""), "ollama is keyless");
        assert_eq!(api_key_env("nope"), None, "an unknown id is not keyless");
    }
}
