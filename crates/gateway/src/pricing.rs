//! Model price catalog → real USD cost for a request's token usage.
//!
//! The gateway threads `gen_ai.usage.cost` onto every span. Providers rarely put
//! a cost on the wire, so without this the dashboard shows token counts but no
//! dollars. This module derives the cost from the response token counts and a
//! per-model list-price table, as a fallback used only when the provider did not
//! report a cost itself (`build_gateway_span`).
//!
//! *list prices* in USD per **million** tokens, entered from each provider's
//! public pricing page. This table is the single place cost is defined; verify it
//! against the provider pages and extend it as models are added. An **unknown
//! model returns `None`** — the gateway never fabricates a cost for a model whose
//! price it does not know (honest-marketing lock, ADR-021/055); the surface shows
//! no cost rather than a wrong one.
//!
//! Cache accounting follows Anthropic's model (the dominant dogfooding path): a
//! cache *read* is billed at 0.1× the input rate, a cache *write* (creation) at
//! 1.25×, and `input_tokens` is the NON-cached remainder. Providers without a
//! discounted cache tier leave those counters unset (`None`), so the formula
//! reduces to `input + output` at the full rate.

use tracelane_shared::Usage;

/// List price for one model, in USD per **million** tokens.
#[derive(Debug, Clone, Copy)]
struct PriceCard {
    input_per_mtok: f64,
    output_per_mtok: f64,
    /// Cache-read (hit) input rate; `0.0` when the provider has no cache tier.
    cache_read_per_mtok: f64,
    /// Cache-write (creation) input rate; `0.0` when the provider has no cache tier.
    cache_write_per_mtok: f64,
}

const MTOK: f64 = 1_000_000.0;

/// Resolve a model string to its price card. Matching is by normalized substring
/// so dated variants (`claude-sonnet-4-6-20260123`) resolve to their family.
/// Returns `None` for a model not in the catalog — callers MUST treat that as
/// "cost unknown", never zero. Only families whose current list price is known
/// with confidence are seeded; the founder adds the rest with verified rates.
fn price_card(model: &str) -> Option<PriceCard> {
    let m = model.to_ascii_lowercase();

    // ── Anthropic Claude ── list prices per Mtok; cache read 0.1×, write 1.25×.
    if m.contains("claude") {
        if m.contains("opus") {
            return Some(PriceCard {
                input_per_mtok: 15.0,
                output_per_mtok: 75.0,
                cache_read_per_mtok: 1.5,
                cache_write_per_mtok: 18.75,
            });
        }
        if m.contains("haiku") {
            return Some(PriceCard {
                input_per_mtok: 1.0,
                output_per_mtok: 5.0,
                cache_read_per_mtok: 0.1,
                cache_write_per_mtok: 1.25,
            });
        }
        if m.contains("sonnet") {
            return Some(PriceCard {
                input_per_mtok: 3.0,
                output_per_mtok: 15.0,
                cache_read_per_mtok: 0.3,
                cache_write_per_mtok: 3.75,
            });
        }
        return None; // an unrecognised Claude tier — do not guess
    }

    // ── OpenAI ── input includes any cached prefix, so we bill input+output at
    // the full rate and leave the cache tiers at 0.0 (no double-count risk).
    if m.contains("gpt-4o-mini") {
        return Some(PriceCard {
            input_per_mtok: 0.15,
            output_per_mtok: 0.60,
            cache_read_per_mtok: 0.0,
            cache_write_per_mtok: 0.0,
        });
    }
    if m.contains("gpt-4o") {
        return Some(PriceCard {
            input_per_mtok: 2.50,
            output_per_mtok: 10.0,
            cache_read_per_mtok: 0.0,
            cache_write_per_mtok: 0.0,
        });
    }

    // ── Google Gemini ── list prices per Mtok, re-verified against
    // ai.google.dev/gemini-api/docs/pricing (2026-07-17, B-111). Vertex charges the
    // SAME per-token rates on the `global` endpoint, so one catalog serves both
    // `gemini-*` (AI Studio) and `vertex/gemini-*`; regional Vertex endpoints carry
    // a ~10% premium that is not modelled (we default to `global`).
    //
    // Flat cards use the base (≤200k-prompt) tier; the >200k tiers for 2.5-pro
    // ($2.50/$15) and 3.1-pro ($4/$18) are NOT modelled here, so a very-large-context
    // request is slightly under-billed (documented approximation, like the OpenAI
    // cache simplification). Gemini's
    // `promptTokenCount` already includes any cached prefix and the adapter does not
    // populate a cache counter for gemini, so cache tiers are 0.0 (bill input+output
    // at the full rate — no double-count). Output tokens here already include
    // thinking (`thoughtsTokenCount`), folded in at extraction (B-104).
    if m.contains("gemini") {
        // B-111: a floating alias resolves to a DIFFERENT concrete model over time,
        // and the caller passes the REQUEST model (`server.rs:1592`), so there is
        // nothing here to resolve it against. Pricing it from any fixed card would
        // be wrong-by-construction the moment Google repoints the alias — so it is
        // deliberately unpriced. Costs nothing today: `-latest` exists only on AI
        // Studio, and AI Studio is the one surface GCP credits can't pay for.
        if m.ends_with("-latest") {
            return None;
        }
        // Gemini 3.x. Ordered most-specific-first; `3.5`/`3.1` can't collide with
        // the `3-flash` arm (the dot breaks the substring) but the order is kept
        // explicit so a later edit can't reintroduce the flash-lite-vs-flash class
        // of bug.
        if m.contains("3.5-flash") {
            return Some(PriceCard {
                input_per_mtok: 1.50,
                output_per_mtok: 9.00,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        if m.contains("3.1-flash-lite") {
            return Some(PriceCard {
                input_per_mtok: 0.25,
                output_per_mtok: 1.50,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        if m.contains("3.1-pro") {
            return Some(PriceCard {
                input_per_mtok: 2.00,
                output_per_mtok: 12.00,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        if m.contains("3-flash") {
            return Some(PriceCard {
                input_per_mtok: 0.50,
                output_per_mtok: 3.00,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        // NOTE: `gemini-3-pro-preview` is deliberately absent — it is NOT LISTED on
        // the pricing page (verified 2026-07-17), so it has no published rate and
        // falls through to `None`. Do not infer one from 3.1-pro.
        if m.contains("2.5-pro") {
            return Some(PriceCard {
                input_per_mtok: 1.25,
                output_per_mtok: 10.0,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        if m.contains("2.5-flash-lite") {
            return Some(PriceCard {
                input_per_mtok: 0.10,
                output_per_mtok: 0.40,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        if m.contains("2.5-flash") {
            return Some(PriceCard {
                input_per_mtok: 0.30,
                output_per_mtok: 2.50,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        // gemini-2.0-flash was DEPRECATED and shut down 2026-06-01 (per the pricing
        // page). Kept so any historical/self-hosted call still prices rather than
        // silently reading $0; it cannot serve new traffic.
        if m.contains("2.0-flash") {
            return Some(PriceCard {
                input_per_mtok: 0.10,
                output_per_mtok: 0.40,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
            });
        }
        return None; // an unrecognised Gemini variant — do not guess
    }

    // Not in the catalog (e.g. a newer family whose list price is not yet
    // entered). Return None — the founder adds it with a verified rate.
    None
}

/// Compute the USD cost of a request from its token usage and the model's list
/// price. Returns `None` when the model is not in the catalog (cost unknown) —
/// never a fabricated zero.
///
/// Billing: `input_tokens` at the input rate + cache-read tokens at the cache-read
/// rate + cache-write tokens at the cache-write rate + `output_tokens` at the
/// output rate, all per million tokens. Cache-read/write tokens are separate
/// counters (Anthropic), not a subset of `input_tokens`, so there is no
/// double-count. A model with no cache tier leaves those counters `None`.
///
/// # Examples
/// ```ignore
/// let u = Usage { input_tokens: 1000, output_tokens: 500, cache_read_input_tokens: None, cache_creation_input_tokens: None };
/// // Claude Sonnet: (1000*3 + 500*15) / 1e6 = 0.0105 USD
/// assert!((cost_usd("claude-sonnet-4-6", &u).unwrap() - 0.0105).abs() < 1e-9);
/// ```
#[must_use]
pub fn cost_usd(model: &str, usage: &Usage) -> Option<f64> {
    let card = price_card(model)?;
    let input = f64::from(usage.input_tokens);
    let output = f64::from(usage.output_tokens);
    let cache_read = f64::from(usage.cache_read_input_tokens.unwrap_or(0));
    let cache_write = f64::from(usage.cache_creation_input_tokens.unwrap_or(0));
    let cost = (input * card.input_per_mtok
        + output * card.output_per_mtok
        + cache_read * card.cache_read_per_mtok
        + cache_write * card.cache_write_per_mtok)
        / MTOK;
    Some(cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: u32, output: u32, cache_read: Option<u32>, cache_write: Option<u32>) -> Usage {
        Usage {
            input_tokens: input,
            output_tokens: output,
            cache_read_input_tokens: cache_read,
            cache_creation_input_tokens: cache_write,
        }
    }

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn sonnet_input_output_cost() {
        // (1000*3 + 500*15) / 1e6 = 0.0105
        let c = cost_usd("claude-sonnet-4-6", &usage(1000, 500, None, None)).unwrap();
        assert!(approx(c, 0.0105), "got {c}");
    }

    #[test]
    fn opus_costs_more_than_sonnet() {
        let opus = cost_usd("claude-opus-4-8", &usage(1000, 1000, None, None)).unwrap();
        let sonnet = cost_usd("claude-sonnet-4-6", &usage(1000, 1000, None, None)).unwrap();
        assert!(approx(opus, 0.09), "opus got {opus}"); // (15000+75000)/1e6
        assert!(opus > sonnet);
    }

    #[test]
    fn haiku_cost() {
        // (1000*1 + 1000*5) / 1e6 = 0.006
        let c = cost_usd("claude-haiku-4-5", &usage(1000, 1000, None, None)).unwrap();
        assert!(approx(c, 0.006), "got {c}");
    }

    /// B-111: the models a NEW Google key can actually call are gemini-3.x — the
    /// 2.5 cards shipped in `46e2043` cover models that 404 (deprecated for new
    /// users) or 429 (billing-gated). This is the live capability matrix, encoded:
    /// if these ever return None again, gemini traffic silently bills $0.
    #[test]
    fn gemini_3x_models_are_priced_from_verified_list_rates() {
        // ai.google.dev/gemini-api/docs/pricing, verified 2026-07-17.
        // (in_per_mtok, out_per_mtok) — output includes thinking tokens per Google.
        for (model, inp, out) in [
            ("gemini-3-flash-preview", 0.50_f64, 3.00_f64),
            ("gemini-3.5-flash", 1.50, 9.00),
            ("gemini-3.1-flash-lite", 0.25, 1.50),
            ("gemini-3.1-pro-preview", 2.00, 12.00),
        ] {
            let c = cost_usd(model, &usage(1_000_000, 1_000_000, None, None))
                .unwrap_or_else(|| panic!("{model} MUST be priced — unpriced gemini bills $0"));
            let want = inp + out;
            assert!(
                (c - want).abs() < 1e-9,
                "{model}: got {c}, want {want} (in {inp} + out {out} per Mtok)"
            );
        }
    }

    /// The routing prefix must not defeat the catalog: Vertex charges the same
    /// per-token rates on the global endpoint, so `vertex/gemini-*` prices exactly
    /// like `gemini-*`. Live-proven 2026-07-17: a real vertex/gemini-2.5-pro span
    /// recorded $0.01534625 for 165 in / 1514 out.
    #[test]
    fn vertex_prefixed_models_price_identically() {
        let bare = cost_usd("gemini-2.5-pro", &usage(165, 1514, None, None)).unwrap();
        let vtx = cost_usd("vertex/gemini-2.5-pro", &usage(165, 1514, None, None)).unwrap();
        assert!(
            (bare - vtx).abs() < 1e-12,
            "vertex prefix changed the price"
        );
        // The exact figure observed on the real prod span.
        assert!(
            (vtx - 0.015_346_25).abs() < 1e-9,
            "regression against the live-proven cost: got {vtx}"
        );
    }

    /// `gemini-3-pro-preview` has NO published rate (NOT LISTED, verified
    /// 2026-07-17). It must stay unpriced rather than inherit 3.1-pro's card —
    /// a fabricated rate mis-bills silently, which is worse than a null.
    #[test]
    fn unlisted_gemini_3_pro_is_none_not_inferred() {
        assert!(cost_usd("gemini-3-pro-preview", &usage(1000, 1000, None, None)).is_none());
    }

    /// Floating aliases resolve to a different model over time and the caller only
    /// has the REQUEST model, so any fixed card would be wrong-by-construction.
    #[test]
    fn floating_latest_aliases_are_unpriced() {
        for m in [
            "gemini-flash-latest",
            "gemini-pro-latest",
            "gemini-flash-lite-latest",
        ] {
            assert!(
                cost_usd(m, &usage(1000, 1000, None, None)).is_none(),
                "{m} must be unpriced — it is a moving target"
            );
        }
    }

    #[test]
    fn gemini_25_pro_priced_from_verified_list_rate() {
        // B-104: gemini-2.5-pro base tier (1.25/10.0): (677*1.25 + 575*10)/1e6.
        // 575 output = candidates+thoughts (the extraction fix feeds cost).
        let c = cost_usd("gemini-2.5-pro", &usage(677, 575, None, None)).unwrap();
        assert!(approx(c, 0.006_596_25), "got {c}");
    }

    #[test]
    fn gemini_flash_lite_matches_before_flash_and_is_cheaper() {
        // "flash-lite" contains "flash" — ordering must match flash-lite FIRST,
        // else a flash-lite request is over-priced at the flash rate.
        let lite = cost_usd("gemini-2.5-flash-lite", &usage(1000, 1000, None, None)).unwrap();
        let flash = cost_usd("gemini-2.5-flash", &usage(1000, 1000, None, None)).unwrap();
        assert!(approx(lite, 0.0005), "flash-lite got {lite}"); // (100+400)/1e6
        assert!(approx(flash, 0.0028), "flash got {flash}"); // (300+2500)/1e6
        assert!(lite < flash);
        // gemini-2.0-flash also priced (0.10/0.40).
        let f20 = cost_usd("gemini-2.0-flash", &usage(1000, 1000, None, None)).unwrap();
        assert!(approx(f20, 0.0005), "2.0-flash got {f20}");
    }

    #[test]
    fn unknown_gemini_variant_is_none_not_zero() {
        // An un-catalogued gemini model returns None — never a fabricated cost
        // (ADR-021/055 honest-marketing lock).
        assert!(cost_usd("gemini-9.9-hypothetical", &usage(1000, 1000, None, None)).is_none());
    }

    #[test]
    fn cache_tokens_are_billed_at_their_discounted_rate() {
        // Sonnet: input 1000@3 + output 500@15 + cache_read 1000@0.3 + cache_write 1000@3.75
        // = (3000 + 7500 + 300 + 3750) / 1e6 = 0.01455
        let c = cost_usd(
            "claude-sonnet-4-6",
            &usage(1000, 500, Some(1000), Some(1000)),
        )
        .unwrap();
        assert!(approx(c, 0.01455), "got {c}");
    }

    #[test]
    fn dated_variant_resolves_to_family() {
        let dated = cost_usd("claude-sonnet-4-6-20260123", &usage(1000, 500, None, None)).unwrap();
        let base = cost_usd("claude-sonnet-4-6", &usage(1000, 500, None, None)).unwrap();
        assert!(approx(dated, base));
    }

    #[test]
    fn openai_models_priced() {
        // gpt-4o: (1000*2.5 + 1000*10)/1e6 = 0.0125
        assert!(approx(
            cost_usd("gpt-4o", &usage(1000, 1000, None, None)).unwrap(),
            0.0125
        ));
        // gpt-4o-mini at 1M+1M = 0.15 + 0.60 = 0.75
        assert!(approx(
            cost_usd("gpt-4o-mini", &usage(1_000_000, 1_000_000, None, None)).unwrap(),
            0.75
        ));
    }

    #[test]
    fn mini_matched_before_base_4o() {
        // "gpt-4o-mini" must not be swallowed by the "gpt-4o" arm.
        let mini = cost_usd("gpt-4o-mini", &usage(1_000_000, 0, None, None)).unwrap();
        assert!(approx(mini, 0.15));
    }

    #[test]
    fn unknown_model_is_none_not_zero() {
        // A model whose price we do not know returns None — never a fake 0.0.
        assert_eq!(
            cost_usd("some-future-model-x", &usage(1000, 1000, None, None)),
            None
        );
        assert_eq!(
            cost_usd("claude-experimental-tier", &usage(1, 1, None, None)),
            None
        );
    }

    #[test]
    fn zero_usage_is_zero_cost_for_known_model() {
        assert_eq!(
            cost_usd("claude-sonnet-4-6", &usage(0, 0, None, None)),
            Some(0.0)
        );
    }
}
