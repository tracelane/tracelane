//! Normalize reported input counts before applying the exclusive price formula.

use tracelane_shared::{SpanAttributes, Usage};

/// The producer knows its own wire convention. The reviewed provider table is
/// only a fallback; unknown or inconsistent cache counts cannot be priced.
pub(crate) fn exclusive_usage(attrs: &SpanAttributes) -> Option<Usage> {
    // The provider wire convention is a code invariant (how each provider's API counts
    // cached input), versioned in git beside the price seed — not a founder-tunable
    // value, so it is embedded rather than seeded (CLAUDE.md §23 covers tunables).
    // A malformed file yields no convention, which leaves cache-bearing spans UNPRICED
    // rather than mispriced — never a panic on the ingest path.
    static CONVENTIONS: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
        serde_json::from_str(include_str!(
            "../../../apps/web/db/usage_conventions.v1.json"
        ))
        .unwrap_or(serde_json::Value::Null)
    });
    let convention = attrs.tracelane_usage_input_includes_cache.or_else(|| {
        let provider = attrs
            .gen_ai_provider_name
            .as_ref()
            .or(attrs.gen_ai_system.as_ref())?;
        match CONVENTIONS.get(provider)?.as_str()? {
            "inclusive" => Some(true),
            "exclusive" => Some(false),
            _ => None,
        }
    });
    let read = attrs.gen_ai_usage_cache_read_input_tokens.unwrap_or(0);
    let write = attrs.gen_ai_usage_cache_creation_input_tokens.unwrap_or(0);
    let cached = read.checked_add(write)?;
    let input = attrs.gen_ai_usage_input_tokens.unwrap_or(0);
    let input_tokens = match convention {
        Some(true) => input.checked_sub(cached)?,
        Some(false) => input,
        None if cached == 0 => input,
        None => return None,
    };
    Some(Usage {
        input_tokens,
        output_tokens: attrs.gen_ai_usage_output_tokens.unwrap_or(0),
        cache_read_input_tokens: attrs.gen_ai_usage_cache_read_input_tokens,
        cache_creation_input_tokens: attrs.gen_ai_usage_cache_creation_input_tokens,
    })
}
