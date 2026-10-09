//! Normalize reported input counts before applying the exclusive price formula.

use serde::Serialize;
use tracelane_shared::{SpanAttributes, Usage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Convention {
    Inclusive,
    Exclusive,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Buckets<T> {
    pub uncached_input: T,
    pub cache_read: T,
    pub cache_write: T,
    pub reasoning: T,
    pub output: T,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UsageView {
    pub convention: Convention,
    pub buckets: Option<Buckets<u32>>,
    pub bucket_cost_usd: Option<Buckets<f64>>,
    pub billed_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub cost_origin: &'static str,
    pub estimated: bool,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub cache_write_tokens: Option<u32>,
    pub reasoning_tokens: Option<u32>,
}

fn input_convention(attrs: &SpanAttributes) -> Convention {
    static CONVENTIONS: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
        serde_json::from_str(include_str!(
            "../../../apps/web/db/usage_conventions.v1.json"
        ))
        .unwrap_or(serde_json::Value::Null)
    });
    match attrs.tracelane_usage_input_includes_cache.or_else(|| {
        let provider = attrs
            .gen_ai_provider_name
            .as_ref()
            .or(attrs.gen_ai_system.as_ref())?;
        match CONVENTIONS.get(provider)?.as_str()? {
            "inclusive" => Some(true),
            "exclusive" => Some(false),
            _ => None,
        }
    }) {
        Some(true) => Convention::Inclusive,
        Some(false) => Convention::Exclusive,
        None => Convention::Unknown,
    }
}

/// Derive display buckets without changing the stored accounting. A producer's
/// cost takes precedence and never receives invented per-bucket prices.
pub(crate) fn breakdown(attrs: &SpanAttributes, origin: Option<&str>) -> UsageView {
    let convention = input_convention(attrs);
    let read = attrs.gen_ai_usage_cache_read_input_tokens.unwrap_or(0);
    let write = attrs.gen_ai_usage_cache_creation_input_tokens.unwrap_or(0);
    let reasoning = attrs.gen_ai_usage_reasoning_output_tokens.unwrap_or(0);
    let buckets = attrs
        .gen_ai_usage_input_tokens
        .zip(attrs.gen_ai_usage_output_tokens)
        .and_then(|(input, output)| {
            let uncached = match convention {
                Convention::Inclusive => input.checked_sub(read.checked_add(write)?)?,
                Convention::Exclusive => input,
                Convention::Unknown => return None,
            };
            Some(Buckets {
                uncached_input: uncached,
                cache_read: read,
                cache_write: write,
                reasoning,
                output: output.checked_sub(reasoning)?,
            })
        });
    let model = attrs
        .gen_ai_response_model
        .as_ref()
        .or(attrs.gen_ai_request_model.as_ref());
    let cost_origin = if attrs.gen_ai_usage_cost.is_none() {
        "unpriced"
    } else {
        match origin {
            Some("provider_reported") => "provider_reported",
            Some("computed") => "computed",
            _ => "unknown",
        }
    };
    let bucket_cost_usd = if cost_origin == "computed" {
        buckets.as_ref().zip(model).and_then(|(b, model)| {
            let one = |input_tokens,
                       output_tokens,
                       cache_read_input_tokens,
                       cache_creation_input_tokens| {
                crate::pricing::cost_usd(
                    model,
                    &Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: Some(cache_read_input_tokens),
                        cache_creation_input_tokens: Some(cache_creation_input_tokens),
                    },
                )
            };
            let costs = Buckets {
                uncached_input: one(b.uncached_input, 0, 0, 0)?,
                cache_read: one(0, 0, b.cache_read, 0)?,
                cache_write: one(0, 0, 0, b.cache_write)?,
                reasoning: one(0, b.reasoning, 0, 0)?,
                output: one(0, b.output, 0, 0)?,
            };
            let sum = costs.uncached_input
                + costs.cache_read
                + costs.cache_write
                + costs.reasoning
                + costs.output;
            (attrs
                .gen_ai_usage_cost
                .is_some_and(|stored| (sum - stored).abs() <= 1e-9))
            .then_some(costs)
        })
    } else {
        None
    };
    let billed_tokens = buckets.as_ref().map(|b| {
        u64::from(b.uncached_input)
            + u64::from(b.cache_read)
            + u64::from(b.cache_write)
            + u64::from(b.reasoning)
            + u64::from(b.output)
    });
    UsageView {
        convention,
        buckets,
        bucket_cost_usd,
        billed_tokens,
        cost_usd: attrs.gen_ai_usage_cost,
        cost_origin,
        estimated: attrs
            .extra
            .get("tracelane_usage_estimated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        input_tokens: attrs.gen_ai_usage_input_tokens,
        output_tokens: attrs.gen_ai_usage_output_tokens,
        cache_read_tokens: attrs.gen_ai_usage_cache_read_input_tokens,
        cache_write_tokens: attrs.gen_ai_usage_cache_creation_input_tokens,
        reasoning_tokens: attrs.gen_ai_usage_reasoning_output_tokens,
    }
}

/// The producer knows its own wire convention. The reviewed provider table is
/// only a fallback; unknown or inconsistent cache counts cannot be priced.
pub(crate) fn exclusive_usage(attrs: &SpanAttributes) -> Option<Usage> {
    let read = attrs.gen_ai_usage_cache_read_input_tokens.unwrap_or(0);
    let write = attrs.gen_ai_usage_cache_creation_input_tokens.unwrap_or(0);
    let cached = read.checked_add(write)?;
    let input = attrs.gen_ai_usage_input_tokens.unwrap_or(0);
    let input_tokens = match input_convention(attrs) {
        Convention::Inclusive => input.checked_sub(cached)?,
        Convention::Exclusive => input,
        Convention::Unknown if cached == 0 => input,
        Convention::Unknown => return None,
    };
    Some(Usage {
        input_tokens,
        output_tokens: attrs.gen_ai_usage_output_tokens.unwrap_or(0),
        cache_read_input_tokens: attrs.gen_ai_usage_cache_read_input_tokens,
        cache_creation_input_tokens: attrs.gen_ai_usage_cache_creation_input_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs59_bucket_conventions_and_cost_origin() {
        let mut attrs = SpanAttributes {
            gen_ai_request_model: Some("claude-sonnet-4-6".into()),
            gen_ai_usage_input_tokens: Some(1234),
            gen_ai_usage_output_tokens: Some(57),
            gen_ai_usage_cache_read_input_tokens: Some(300),
            gen_ai_usage_cache_creation_input_tokens: Some(12),
            tracelane_usage_input_includes_cache: Some(false),
            ..Default::default()
        };
        let usage = exclusive_usage(&attrs).unwrap();
        attrs.gen_ai_usage_cost = crate::pricing::cost_usd("claude-sonnet-4-6", &usage);
        let exclusive = breakdown(&attrs, Some("computed"));
        assert_eq!(exclusive.buckets.as_ref().unwrap().uncached_input, 1234);
        let costs = exclusive.bucket_cost_usd.as_ref().unwrap();
        let sum = costs.uncached_input
            + costs.cache_read
            + costs.cache_write
            + costs.reasoning
            + costs.output;
        assert!((sum - attrs.gen_ai_usage_cost.unwrap()).abs() <= 1e-9);
        assert_eq!(exclusive.billed_tokens, Some(1603));

        attrs.gen_ai_usage_input_tokens = Some(1546);
        attrs.tracelane_usage_input_includes_cache = Some(true);
        assert_eq!(
            breakdown(&attrs, Some("computed"))
                .buckets
                .unwrap()
                .uncached_input,
            1234
        );
        assert!(
            breakdown(&attrs, Some("provider_reported"))
                .bucket_cost_usd
                .is_none()
        );
        assert!(breakdown(&attrs, None).bucket_cost_usd.is_none());
        attrs.tracelane_usage_input_includes_cache = None;
        assert!(breakdown(&attrs, Some("computed")).buckets.is_none());
        attrs.tracelane_usage_input_includes_cache = Some(true);
        attrs.gen_ai_usage_input_tokens = Some(100);
        assert!(breakdown(&attrs, Some("computed")).buckets.is_none());
    }

    #[test]
    fn obs59_bucket_costs_sum_for_every_resolvable_catalog_model() {
        let mut checked = 0;
        for line in include_str!("../model_prices.tsv").lines() {
            let mut fields = line.split('\t');
            let (Some(provider), Some(model)) = (fields.next(), fields.next()) else {
                continue;
            };
            if provider == "provider" || provider.starts_with('#') {
                continue;
            }
            let attrs = SpanAttributes {
                gen_ai_request_model: Some(model.to_string()),
                gen_ai_usage_input_tokens: Some(1234),
                gen_ai_usage_output_tokens: Some(57),
                gen_ai_usage_cache_read_input_tokens: Some(300),
                gen_ai_usage_cache_creation_input_tokens: Some(12),
                tracelane_usage_input_includes_cache: Some(false),
                ..Default::default()
            };
            let Some(stored) = crate::pricing::cost_usd(model, &exclusive_usage(&attrs).unwrap())
            else {
                continue;
            };
            let attrs = SpanAttributes {
                gen_ai_usage_cost: Some(stored),
                ..attrs
            };
            let view = breakdown(&attrs, Some("computed"));
            let costs = view
                .bucket_cost_usd
                .unwrap_or_else(|| panic!("missing bucket costs for {model}"));
            let sum = costs.uncached_input
                + costs.cache_read
                + costs.cache_write
                + costs.reasoning
                + costs.output;
            assert!((sum - stored).abs() <= 1e-9, "cost mismatch for {model}");
            checked += 1;
        }
        assert!(
            checked > 100,
            "catalog test must cover models, not an empty fixture"
        );
    }
}
