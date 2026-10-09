//! Model price catalog → real USD cost for a request's token usage.
//!
//! The gateway threads `gen_ai.usage.cost` onto every span. Providers rarely put
//! a cost on the wire, so without this the dashboard shows token counts but no
//! dollars. This module derives the cost from the response token counts and a
//! per-model list-price table, as a fallback used only when the provider did not
//! report a cost itself (`build_gateway_span`).
//!
//! **Maintenance:** the hand-verified rates below are provider
//! *list prices* in USD per **million** tokens, entered from each provider's
//! public pricing page and take precedence over the generated catalog. Verify them
//! against the provider pages and extend them as models are added. An **unknown
//! model returns `None`** — the gateway never fabricates a cost for a model whose
//! price it does not know (honest-marketing lock, ADR-021/055); the surface shows
//! no cost rather than a wrong one.
//!
//! Cache rates are provider-specific. `input_tokens` is the non-cached remainder
//! when an adapter supplies separate cache counters. An adapter that does not
//! supply them bills its inclusive input counter at the full input rate.

use std::borrow::Cow;
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
    /// `OG-05`: the long-context tier, when the vendor charges more above a
    /// prompt-size threshold. `None` for a flat-rate model.
    long_context: Option<LongContext>,
}

/// A vendor's long-context surcharge: once the WHOLE prompt exceeds
/// `threshold_tokens`, every input-side rate is multiplied by `input_mult` and
/// the output rate by `output_mult` (OpenAI >272K: 2x / 1.5x; Gemini 3.1 Pro
/// >200K: 2x / 1.5x; xAI Grok 4.7 at or above 200K: 2x / 2x).
#[derive(Debug, Clone, Copy)]
struct LongContext {
    threshold_tokens: u32,
    input_mult: f64,
    output_mult: f64,
}

impl PriceCard {
    /// A flat card from the vendor's (input, cached-input read, output) list
    /// prices, USD per Mtok. Cache WRITE is `0.0`: the vendors using this
    /// constructor publish no write tier (their caching is implicit).
    const fn flat(input: f64, cache_read: f64, output: f64) -> Self {
        Self {
            input_per_mtok: input,
            output_per_mtok: output,
            cache_read_per_mtok: cache_read,
            cache_write_per_mtok: 0.0,
            long_context: None,
        }
    }

    /// Add a long-context tier to a card.
    const fn long(mut self, threshold_tokens: u32, input_mult: f64, output_mult: f64) -> Self {
        self.long_context = Some(LongContext {
            threshold_tokens,
            input_mult,
            output_mult,
        });
        self
    }

    /// Record a published cache-creation rate when it differs from the default.
    const fn cache_write(mut self, rate: f64) -> Self {
        self.cache_write_per_mtok = rate;
        self
    }
}

/// Does `bare` name exactly `name`, or a DATED snapshot of it (`name-2026-10-01`)?
/// `gpt-5.5` must not capture `gpt-5.5-mini` or `gpt-5.5-pro`, which are other
/// models at other prices; a `starts_with` would.
fn is_model(bare: &str, name: &str) -> bool {
    bare == name
        || bare
            .strip_prefix(name)
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
}

const MTOK: f64 = 1_000_000.0;

/// The models that carry a hand-verified card (`OG-05` §3.2, verified
/// 2026-10-08), in the order `GET /v1/models` lists them. Kept beside the cards
/// so one edit moves both; `models_list::tests::every_listed_model_routes_and_has_a_verified_card`
/// fails if an entry is unroutable or unpriced.
pub const VERIFIED_FRONTIER_MODELS: &[&str] = &[
    "gpt-6-astra",
    "gpt-6.1-sol",
    "gpt-6-sol",
    "gpt-6-luna",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
    "gpt-5.6-cyber",
    "gpt-5.5",
    "gpt-5.5-pro",
    "gpt-5.3-codex",
    "claude-fable-5-1",
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
    "claude-haiku-4-5",
    "gemini-3.1-pro-preview",
    "gemini-3.8-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "grok-4.7",
    "grok-4.3",
    "grok-build-0.1",
    "deepseek-flash",
    "deepseek-v4-pro",
    "kimi-k3",
    "kimi-k2.7-code",
    "kimi-k2.6",
    "glm-5.3",
    "glm-5.3-flash",
    "glm-5.3-flashx",
    "qwen3.8-max",
    "qwen3.7-plus",
    "qwen3.8-flash",
];

/// Resolve a model string to its price card. Matching is by normalized substring
/// so dated variants (`claude-sonnet-4-6-20260123`) resolve to their family.
/// Returns `None` for a model not in the catalog — callers MUST treat that as
/// "cost unknown", never zero. Only families whose current list price is known
/// with confidence are seeded; the founder adds the rest with verified rates.
fn price_card(model: &str) -> Option<PriceCard> {
    let m = model.to_ascii_lowercase();
    let (route_prefix, bare) = match m.split_once('/') {
        Some((p, rest)) => (Some(p), rest),
        None => (None, m.as_str()),
    };

    // ── Anthropic Claude ── list prices per Mtok, re-verified against
    // https://platform.claude.com/docs/en/about-claude/pricing on 2026-10-08.
    // Cache read is 0.1× input (0.025× on Fable / Mythos 5.1); the 5-minute
    // cache write is 1.25× input. The 1-hour write tier (2× input) is NOT
    // modelled: the adapter reports one cache-creation counter, so a 1h write
    // bills at the 5m rate — a documented under-report on that slice only.
    if matches!(route_prefix, None | Some("anthropic")) && bare.starts_with("claude-") {
        // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
        // Fable 5 / 5.1 and Mythos 5 / 5.1: 10/50. Only the 5.1 generation has
        // the 0.025× cache read; Fable 5 / Mythos 5 read at the standard 0.1×.
        if m.contains("fable") || m.contains("mythos") {
            let cache_read = if m.contains("-5-1") { 0.25 } else { 1.0 };
            return Some(PriceCard {
                input_per_mtok: 10.0,
                output_per_mtok: 50.0,
                cache_read_per_mtok: cache_read,
                cache_write_per_mtok: 12.5,
                long_context: None,
            });
        }
        if m.contains("opus") {
            // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
            // Opus 5.5 is 4 / 0.20 cache read / 20 — cheaper than Opus 5.
            // It MUST sit before the `opus-5` arm below, whose
            // substring also matches `opus-5-5`; the 5-minute cache write is
            // 1.25x input.
            if m.contains("opus-5-5") {
                return Some(PriceCard {
                    input_per_mtok: 4.0,
                    output_per_mtok: 20.0,
                    cache_read_per_mtok: 0.2,
                    cache_write_per_mtok: 5.0,
                    long_context: None,
                });
            }
            // Opus 4.5, 4.6, 4.7, 4.8 and 5 are 5/25. Opus 4 and 4.1 (retired
            // except on Bedrock / Google Cloud) and Claude 3 Opus are 15/75.
            // Until 2026-09-07 EVERY "opus" priced at 15/75 — 3× over for every
            // Opus a customer can call today (B-350, found when the models.dev
            // catalog refresh disagreed with this card; the page settled it).
            const OPUS_AT_5_25: [&str; 5] =
                ["opus-4-5", "opus-4-6", "opus-4-7", "opus-4-8", "opus-5"];
            if OPUS_AT_5_25.iter().any(|v| m.contains(v)) {
                // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
                return Some(PriceCard {
                    input_per_mtok: 5.0,
                    output_per_mtok: 25.0,
                    cache_read_per_mtok: 0.5,
                    cache_write_per_mtok: 6.25,
                    long_context: None,
                });
            }
            // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
            return Some(PriceCard {
                input_per_mtok: 15.0,
                output_per_mtok: 75.0,
                cache_read_per_mtok: 1.5,
                cache_write_per_mtok: 18.75,
                long_context: None,
            });
        }
        if m.contains("haiku") {
            // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
            if m.contains("haiku-5-5") {
                return Some(
                    PriceCard {
                        input_per_mtok: 0.10,
                        output_per_mtok: 0.50,
                        cache_read_per_mtok: 0.01,
                        cache_write_per_mtok: 0.125,
                        long_context: None,
                    }
                    .long(100_000, 5.0, 5.0),
                );
            }
            // Haiku 3.5 (retired except on Bedrock / Google Cloud) is 0.80/4;
            // Haiku 4.5 is 1/5.
            if m.contains("haiku-3-5") || m.contains("3-5-haiku") {
                // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
                return Some(PriceCard {
                    input_per_mtok: 0.8,
                    output_per_mtok: 4.0,
                    cache_read_per_mtok: 0.08,
                    cache_write_per_mtok: 1.0,
                    long_context: None,
                });
            }
            // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
            return Some(PriceCard {
                input_per_mtok: 1.0,
                output_per_mtok: 5.0,
                cache_read_per_mtok: 0.1,
                cache_write_per_mtok: 1.25,
                long_context: None,
            });
        }
        if m.contains("sonnet") {
            // Sonnet 5 is 2/10 — the launch "introductory" price made permanent
            // (the page says the scheduled 2026-09-01 rise to 3/15 will not
            // occur). Sonnet 4, 4.5 and 4.6 are 3/15. `sonnet-5` cannot match
            // `sonnet-4-5` (different substring) — asserted in the tests.
            if m.contains("sonnet-5") {
                // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
                return Some(PriceCard {
                    input_per_mtok: 2.0,
                    output_per_mtok: 10.0,
                    // Sonnet 5.5 alone has the 5% cache-read tier.
                    // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
                    cache_read_per_mtok: if m.contains("sonnet-5-5") { 0.10 } else { 0.20 },
                    cache_write_per_mtok: 2.5,
                    long_context: None,
                });
            }
            // Source: https://platform.claude.com/docs/en/about-claude/pricing (2026-10-08).
            return Some(PriceCard {
                input_per_mtok: 3.0,
                output_per_mtok: 15.0,
                cache_read_per_mtok: 0.3,
                cache_write_per_mtok: 3.75,
                long_context: None,
            });
        }
        return None; // an unrecognised Claude tier — do not guess
    }

    // ── DeepSeek, first-party API ── PEAK list prices per Mtok from
    // https://api-docs.deepseek.com/quick_start/pricing, verified 2026-10-08 (OG-05):
    // `deepseek-flash` 0.30 / 0.006 cache hit / 1.20, `deepseek-v4-pro`
    // 1.32 / 0.044 / 3.96 (peak = Mon-Fri 01:00-04:00 and 06:00-10:00 UTC;
    // off-peak is exactly half: 0.15/0.003/0.60 and 0.66/0.022/1.98). A request is
    // priced by model, not by wall clock, so the card carries the PEAK rate and
    // off-peak traffic is OVER-reported by 2x. That is B-351's ruling, kept
    // deliberately by the coordinator over the OG-05 builder's off-peak proposal:
    // this number feeds BUDGET ENFORCEMENT (key / workspace ceilings), and a
    // budget built on an under-report can be overspent, while an over-report
    // only stops a customer early. Money controls err on the safe side (§10).
    // ponytail: peak/off-peak is not modelled so off-peak spend is over-reported 2x, upgrade is a UTC-hour window on the span start time held in a reference table (CLAUDE.md §23).
    //
    // The OpenAI-compatible adapter reports `prompt_tokens` (cache hits
    // included) as input and no cache counters, so input bills at the cache-MISS
    // rate (the cache-hit rate is therefore never applied; over-report on that
    // slice).
    //
    // `deepseek-chat` / `deepseek-reasoner` are the legacy names: since
    // 2026-07-31 both point at V4-Flash (non-thinking / thinking) and DeepSeek
    // retires them three months on (api-docs.deepseek.com/updates). They price on
    // the Flash card and this arm goes when the names do.
    //
    // Why hand cards at all: models.dev still carries older rates for
    // `deepseek/deepseek-v4-*`, so the generated row can be stale; the hand card
    // wins over it by design. Scoped to the first-party route — a
    // `groq/deepseek-r1-…` or other reseller id falls through to the catalog,
    // which prices it from that reseller's own row.
    if matches!(route_prefix, None | Some("deepseek")) && bare.starts_with("deepseek") {
        if bare.contains("v4-pro") {
            // Source: https://api-docs.deepseek.com/quick_start/pricing (2026-10-08).
            return Some(PriceCard::flat(1.32, 0.044, 3.96));
        }
        if bare.contains("v4-flash")
            || bare.contains("deepseek-flash")
            || bare == "deepseek-chat"
            || bare == "deepseek-reasoner"
        {
            // Source: https://api-docs.deepseek.com/quick_start/pricing (2026-10-08).
            return Some(PriceCard::flat(0.30, 0.006, 1.20));
        }
        // R1 / V3.x first-party ids are no longer on DeepSeek's price page —
        // fall through to the catalog rather than guess.
    }

    // ── OG-05 first-party cards. Each is scoped to the vendor's OWN route
    // (`None` = a bare id, or the vendor's own `provider/` prefix), so a
    // reseller's `together/moonshotai/Kimi-…` or `openrouter/openai/gpt-…`
    // falls through to the catalog and is priced from THAT reseller's row, and
    // a first-party id is never priced from a reseller's row. List prices, USD
    // per Mtok as (input, cached-input read, output), verified 2026-10-08.
    // `is_model` matches the exact id or a dated snapshot of it, so a sibling
    // (`gpt-5.5-pro` vs `gpt-5.5`) can never take another model's price.

    // xAI — https://docs.x.ai/developers/pricing (2026-10-08). Grok doubles at or above 200K prompt
    // tokens (4 / 1.00 / 12); `> 199_999` is "at or above 200,000".
    if matches!(route_prefix, None | Some("xai")) {
        if is_model(bare, "grok-4.7") {
            // Source: https://docs.x.ai/developers/pricing (2026-10-08).
            return Some(PriceCard::flat(2.0, 0.50, 6.0).long(199_999, 2.0, 2.0));
        }
        if is_model(bare, "grok-4.3") {
            // Source: https://docs.x.ai/developers/pricing (2026-10-08).
            return Some(PriceCard::flat(1.25, 0.20, 2.5).long(199_999, 2.0, 2.0));
        }
        if is_model(bare, "grok-build-0.1") {
            // Source: https://docs.x.ai/developers/pricing (2026-10-08).
            return Some(PriceCard::flat(1.0, 0.20, 2.0).long(199_999, 2.0, 2.0));
        }
    }

    // Moonshot international (https://platform.kimi.ai/, 2026-10-08) — the `kimi-` bare prefix
    // routes to `moonshot-intl`. The China host `moonshot` is priced in CNY and
    // is deliberately NOT given this card.
    if matches!(route_prefix, None | Some("moonshot-intl")) {
        if is_model(bare, "kimi-k3") {
            // Source: https://platform.kimi.ai/ (2026-10-08).
            return Some(PriceCard::flat(3.0, 0.30, 15.0).cache_write(3.0));
        }
        if is_model(bare, "kimi-k2.7-code") {
            // Source: https://platform.kimi.ai/ (2026-10-08).
            return Some(PriceCard::flat(0.95, 0.19, 4.0));
        }
        if is_model(bare, "kimi-k2.6") {
            // Source: https://platform.kimi.ai/ (2026-10-08).
            return Some(PriceCard::flat(0.95, 0.16, 4.0));
        }
    }

    // Z.ai — https://docs.z.ai/guides/overview/pricing (2026-10-08).
    if matches!(route_prefix, None | Some("zai")) {
        if is_model(bare, "glm-5.3-flashx") {
            // Source: https://docs.z.ai/guides/overview/pricing (2026-10-08).
            return Some(PriceCard::flat(0.37, 0.075, 1.25));
        }
        if is_model(bare, "glm-5.3-flash") {
            // Source: https://docs.z.ai/guides/overview/pricing (2026-10-08).
            return Some(PriceCard::flat(0.15, 0.03, 0.50));
        }
        if is_model(bare, "glm-5.3") {
            // Source: https://docs.z.ai/guides/overview/pricing (2026-10-08).
            return Some(PriceCard::flat(1.4, 0.26, 4.4));
        }
    }

    // Alibaba Model Studio international — https://www.alibabacloud.com/help/en/model-studio/model-pricing
    // (2026-10-08). Implicit cache hits cost 20% of input per
    // https://www.alibabacloud.com/help/en/model-studio/context-cache (2026-10-08).
    if matches!(route_prefix, None | Some("alibaba")) {
        if is_model(bare, "qwen3.8-max") {
            // Source: both Alibaba pages above (2026-10-08).
            return Some(PriceCard::flat(2.0, 0.40, 6.0));
        }
        if is_model(bare, "qwen3.7-plus") {
            // Source: both Alibaba pages above (2026-10-08); Singapore >256K is 3x.
            return Some(PriceCard::flat(0.4, 0.08, 1.6).long(256_000, 3.0, 3.0));
        }
        if is_model(bare, "qwen3.8-flash") {
            // Source: both Alibaba pages above (2026-10-08).
            return Some(PriceCard::flat(0.15, 0.03, 0.47));
        }
    }

    // OpenAI — https://developers.openai.com/api/docs/pricing (2026-10-08). Above 272K input tokens
    // gpt-6-astra, gpt-6.1-sol, gpt-6-sol and gpt-6-luna bill 2x input and 1.5x output
    // (`.long`). `gpt-5.5-pro` has no cached-input tier (`0.0`; the adapter
    // reports no cache counter, so it never applies).
    if matches!(route_prefix, None | Some("openai")) {
        if is_model(bare, "gpt-6-astra") {
            // Source: https://developers.openai.com/api/docs/pricing (2026-10-08).
            return Some(
                PriceCard::flat(10.0, 1.0, 50.0)
                    .cache_write(12.5)
                    .long(272_000, 2.0, 1.5),
            );
        }
        if is_model(bare, "gpt-6.1-sol") {
            // Source: https://developers.openai.com/api/docs/pricing (2026-10-08).
            return Some(
                PriceCard::flat(2.0, 0.10, 10.0)
                    .cache_write(2.5)
                    .long(272_000, 2.0, 1.5),
            );
        }
        if is_model(bare, "gpt-6-sol") {
            // Source: https://developers.openai.com/api/docs/models/gpt-6-sol (2026-10-08).
            return Some(
                PriceCard::flat(2.0, 0.20, 10.0)
                    .cache_write(2.5)
                    .long(272_000, 2.0, 1.5),
            );
        }
        if is_model(bare, "gpt-6-luna") {
            // Source: https://developers.openai.com/api/docs/pricing (2026-10-08).
            return Some(
                PriceCard::flat(0.10, 0.01, 0.50)
                    .cache_write(0.125)
                    .long(272_000, 2.0, 1.5),
            );
        }
        if is_model(bare, "gpt-5.6-sol") || is_model(bare, "gpt-5.6") {
            // Source: https://developers.openai.com/api/docs/models/gpt-5.6-sol (2026-10-08).
            return Some(
                PriceCard::flat(4.0, 0.4, 20.0)
                    .cache_write(5.0)
                    .long(272_000, 2.0, 1.5),
            );
        }
        if is_model(bare, "gpt-5.6-terra") {
            // Source: https://developers.openai.com/api/docs/models/gpt-5.6-terra (2026-10-08).
            return Some(
                PriceCard::flat(2.0, 0.2, 12.0)
                    .cache_write(2.5)
                    .long(272_000, 2.0, 1.5),
            );
        }
        if is_model(bare, "gpt-5.6-luna") {
            // Source: https://developers.openai.com/api/docs/models/gpt-5.6-luna (2026-10-08).
            return Some(
                PriceCard::flat(0.2, 0.02, 1.2)
                    .cache_write(0.25)
                    .long(272_000, 2.0, 1.5),
            );
        }
        if is_model(bare, "gpt-5.6-cyber") {
            // Source: https://developers.openai.com/api/docs/pricing (2026-10-08).
            // The pricing table lists no long tier; the model page says a long-tier rule.
            return Some(PriceCard::flat(12.5, 1.25, 75.0).cache_write(15.625));
        }
        if is_model(bare, "gpt-5.5-pro") {
            // Source: https://developers.openai.com/api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(30.0, 0.0, 180.0));
        }
        if is_model(bare, "gpt-5.5") {
            // Source: https://developers.openai.com/api/docs/models/gpt-5.5 (2026-10-08).
            return Some(PriceCard::flat(5.0, 0.5, 30.0).long(272_000, 2.0, 1.5));
        }
        if is_model(bare, "gpt-5.3-codex") {
            // Source: https://developers.openai.com/api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(1.75, 0.175, 14.0));
        }
    }

    // ── OpenAI ── input includes any cached prefix in the current adapter;
    // its separate cache counters remain unset, so a published cache rate in
    // the card does not double-count that inclusive input.
    if matches!(route_prefix, None | Some("openai")) && is_model(bare, "gpt-4o-mini") {
        // Source: https://developers.openai.com/api/docs/models/gpt-4o-mini (2026-10-08).
        return Some(PriceCard {
            input_per_mtok: 0.15,
            output_per_mtok: 0.60,
            cache_read_per_mtok: 0.075,
            cache_write_per_mtok: 0.0,
            long_context: None,
        });
    }
    if matches!(route_prefix, None | Some("openai")) && is_model(bare, "gpt-4o") {
        // Source: https://developers.openai.com/api/docs/models/gpt-4o (2026-10-08).
        return Some(PriceCard {
            input_per_mtok: 2.50,
            output_per_mtok: 10.0,
            cache_read_per_mtok: 1.25,
            cache_write_per_mtok: 0.0,
            long_context: None,
        });
    }

    // ── Google Gemini ── list prices per Mtok, re-verified against
    // https://ai.google.dev/gemini-api/docs/pricing (2026-10-08). Vertex charges the
    // SAME per-token rates on the `global` endpoint, so one catalog serves both
    // `gemini-*` (AI Studio) and `vertex/gemini-*`; regional Vertex endpoints carry
    // a ~10% premium that is not modelled (we default to `global`).
    //
    // Gemini 2.5 Pro and 3.1 Pro both use `PriceCard::long`. Gemini's
    // `promptTokenCount` already includes any cached prefix and the adapter does not
    // populate a cache counter for gemini, so the published card cache tiers
    // do not currently apply to actual Gemini spans. Output tokens here already include
    // thinking (`thoughtsTokenCount`), folded in at extraction.
    if matches!(route_prefix, None | Some("google") | Some("vertex")) && bare.starts_with("gemini-")
    {
        // A floating alias resolves to a DIFFERENT concrete model over time,
        // and the caller passes the REQUEST model (`server.rs:1592`), so there is
        // nothing here to resolve it against. Pricing it from any fixed card would
        // be wrong-by-construction the moment Google repoints the alias — so it is
        // deliberately unpriced. Costs nothing today: `-latest` exists only on AI
        // Studio, and AI Studio is the one surface GCP credits can't pay for.
        if bare.ends_with("-latest") {
            return None;
        }
        // Gemini 3.x. Ordered most-specific-first; `3.5`/`3.1` can't collide with
        // the `3-flash` arm (the dot breaks the substring) but the order is kept
        // explicit so a later edit can't reintroduce the flash-lite-vs-flash class
        // of bug.
        // OG-05: verified 2026-10-01 against ai.google.dev/gemini-api/docs/pricing,
        // as (input, cached-input read, output) USD per Mtok. `3.8-flash` MUST NOT
        // capture `3.8-flash-lite` (a different, unlisted model): it is left to the
        // `None` fall-through below rather than priced at the Flash rate.
        if is_model(bare, "gemini-3.8-flash") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(0.75, 0.075, 3.75));
        }
        if is_model(bare, "gemini-3.5-flash-lite") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(0.30, 0.03, 2.50));
        }
        if is_model(bare, "gemini-3.5-flash") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(1.50, 0.15, 9.00));
        }
        if is_model(bare, "gemini-3.1-flash-lite") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(0.25, 0.025, 1.50));
        }
        // Gemini 3.1 Pro: 2 / 0.20 / 12 up to 200K prompt tokens, 4 / 0.40 / 18
        // above it (2x input side, 1.5x output) — modelled via `.long`.
        if is_model(bare, "gemini-3.1-pro-preview") || is_model(bare, "gemini-3.1-pro") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(2.00, 0.20, 12.00).long(200_000, 2.0, 1.5));
        }
        if is_model(bare, "gemini-3-flash-preview") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(0.50, 0.05, 3.00));
        }
        // NOTE: `gemini-3-pro-preview` is deliberately absent — it is NOT LISTED on
        // the pricing page (verified 2026-07-17), so it has no published rate and
        // falls through to `None`. Do not infer one from 3.1-pro.
        if is_model(bare, "gemini-2.5-pro") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(1.25, 0.125, 10.0).long(200_000, 2.0, 1.5));
        }
        if is_model(bare, "gemini-2.5-flash-lite") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(0.10, 0.01, 0.40));
        }
        if is_model(bare, "gemini-2.5-flash") {
            // Source: https://ai.google.dev/gemini-api/docs/pricing (2026-10-08).
            return Some(PriceCard::flat(0.30, 0.03, 2.50));
        }
        // gemini-2.0-flash was DEPRECATED and shut down 2026-06-01 (per the pricing
        // page). Kept so any historical/self-hosted call still prices rather than
        // silently reading $0; it cannot serve new traffic.
        if is_model(bare, "gemini-2.0-flash") {
            return Some(PriceCard {
                input_per_mtok: 0.10,
                output_per_mtok: 0.40,
                cache_read_per_mtok: 0.0,
                cache_write_per_mtok: 0.0,
                long_context: None,
            });
        }
        return None; // an unrecognised Gemini variant — do not guess
    }

    // Not in the catalog (e.g. a newer family whose list price is not yet
    // entered). Return None — the founder adds it with a verified rate.
    None
}

fn price_model<'a>(
    requested: &'a str,
    alias: Option<&crate::server::config::ModelAlias>,
) -> Cow<'a, str> {
    match alias {
        // An operator alias may reuse a first-party model name while routing to
        // another provider. Price the provider and model actually sent upstream.
        Some(a) => Cow::Owned(format!("{}/{}", a.provider_id, a.upstream_model)),
        None => Cow::Borrowed(requested),
    }
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
    let card = price_card(model).or_else(|| catalog_card(model))?;
    Some(cost_from_card(card, usage))
}

fn cost_from_card(card: PriceCard, usage: &Usage) -> f64 {
    let input = f64::from(usage.input_tokens);
    let output = f64::from(usage.output_tokens);
    let cache_read = f64::from(usage.cache_read_input_tokens.unwrap_or(0));
    let cache_write = f64::from(usage.cache_creation_input_tokens.unwrap_or(0));
    // Long-context tier: the vendor's threshold is on the WHOLE prompt, cached
    // prefix included, so the three input-side counters are summed.
    let (in_mult, out_mult) = match card.long_context {
        Some(lc) if input + cache_read + cache_write > f64::from(lc.threshold_tokens) => {
            (lc.input_mult, lc.output_mult)
        }
        _ => (1.0, 1.0),
    };
    ((input * card.input_per_mtok
        + cache_read * card.cache_read_per_mtok
        + cache_write * card.cache_write_per_mtok)
        * in_mult
        + output * card.output_per_mtok * out_mult)
        / MTOK
}

/// Price an online request using its configured route. External OTLP records
/// use `cost_usd` directly: their model names did not necessarily pass through
/// this gateway's operator aliases.
#[must_use]
pub fn cost_usd_for_routed_model(
    requested: &str,
    alias: Option<&crate::server::config::ModelAlias>,
    usage: &Usage,
) -> Option<f64> {
    let Some(alias) = alias else {
        return cost_usd(requested, usage);
    };
    let priced_model = price_model(requested, Some(alias));
    let card = price_card(&priced_model)
        .or_else(|| catalog_card_for_provider(&priced_model, &alias.provider_id))?;
    Some(cost_from_card(card, usage))
}

/// ── The generated price table (GWY-42) ──────────────────────────────────────
///
/// `price_card` above is the hand-verified set across first-party vendors,
/// each entered from a provider's own pricing page. It stays FIRST and it WINS.
/// This table only extends coverage.
///
/// **Why coverage was the emergency.** `price_card` answered `None` for gpt-5,
/// gpt-4.1, o1, o3, every `text-embedding-*`, and every Groq / Mistral /
/// DeepSeek / xAI / Perplexity model — i.e. for most of what a customer would
/// actually route. `None` is honest at this seam, but it does not survive the
/// journey: `#[serde(skip_serializing_if)]` drops the attribute from the span,
/// and every read-side SQL wraps the extract in `if(isFinite AND > 0, …, 0)`.
/// So unpriced traffic arrived at the dashboard's "Spend (est.)" tile as
/// **$0.00** — a wrong number wearing the confidence of a right one. Budgets
/// (Sprint 1 item 2) and per-key attribution (item 5) both build on this
/// number, so the coverage gap was theirs too.
///
/// Rows are `provider \t model \t input \t output \t cache_read`, USD per Mtok,
/// generated from models.dev (MIT) by `scripts/ci/build-provider-catalog.py`.
mod catalog_prices {
    use std::collections::HashMap;
    use std::sync::OnceLock;

    const TSV: &str = include_str!("../model_prices.tsv");

    /// `input`, `output`, `cache_read` — USD per million tokens. `cache_read` is
    /// `None` when the vendor publishes no discounted cache rate, which the
    /// caller charges at the full input rate rather than assuming away.
    type Rates = (f64, f64, Option<f64>);
    /// `(provider_id, model)` → rates. Named so the signature reads.
    type PriceTable = HashMap<(&'static str, &'static str), Rates>;

    /// `(provider_id, model)` → `(input, output, cache_read)`. `provider_id` is
    /// `*` for the unambiguous-bare-name fallback rows — emitted only when
    /// exactly ONE provider sells that model id, so a bare `gpt-4o` prices from
    /// its real owner and an ambiguous name gets no fallback rather than a coin
    /// toss between two vendors' rates.
    // B-386: stays global — this is a memoised parse of a compile-time constant
    // (`model_prices.tsv`), with no input, no mutation and no test setup; moving
    // it into `AppState` would thread an argument through `build_gateway_span`'s
    // sites and the two finalizers to construct the same table.
    pub fn table() -> &'static PriceTable {
        static T: OnceLock<PriceTable> = OnceLock::new();
        T.get_or_init(|| {
            let mut m = HashMap::new();
            for line in TSV.lines() {
                let line = line.trim_end_matches('\r');
                if line.is_empty() || line.starts_with('#') || line.starts_with("provider\t") {
                    continue;
                }
                let mut f = line.split('\t');
                let (Some(p), Some(model), Some(i), Some(o)) =
                    (f.next(), f.next(), f.next(), f.next())
                else {
                    continue;
                };
                let cr = f.next().and_then(|v| v.parse::<f64>().ok());
                let (Ok(i), Ok(o)) = (i.parse::<f64>(), o.parse::<f64>()) else {
                    continue;
                };
                m.insert((p, model), (i, o, cr));
            }
            m
        })
    }
}

/// Look a model up in the generated table.
///
/// Tried in order: `(provider, model)` → `(provider, model minus its
/// `provider/` prefix)` → `(*, model)`. The provider comes from the ONE
/// canonical map, so a model that is unroutable is also unpriced — which is
/// correct: we do not know who would have sold it.
///
/// **Cache rates are deliberately conservative.** models.dev publishes a
/// cache-READ rate and no cache-WRITE rate. An unknown discount is charged at
/// the full input rate rather than assumed away: under-reporting cost is the
/// direction that silently overspends a budget, and budgets are built on this
/// number.
fn catalog_card(model: &str) -> Option<PriceCard> {
    let t = catalog_prices::table();
    let provider = crate::providers::ProviderRegistry::provider_id_for_model(model);

    let hit = provider
        .and_then(|p| t.get(&(p, model)))
        .or_else(|| {
            let p = provider?;
            // `groq/llama-3.3-70b` is sold as `llama-3.3-70b`; strip our routing
            // prefix, which is ours and never goes on the vendor's price list.
            let bare = model.split_once('/').map(|(_, rest)| rest)?;
            t.get(&(p, bare))
        })
        .or_else(|| t.get(&("*", model)))?;

    let (input, output, cache_read) = *hit;
    Some(PriceCard {
        input_per_mtok: input,
        output_per_mtok: output,
        cache_read_per_mtok: cache_read.unwrap_or(input),
        cache_write_per_mtok: input,
        long_context: None,
    })
}

/// An operator alias already names its actual provider. Do not re-run alias
/// resolution on the synthetic `provider/model` key, and do not use a `*`
/// fallback owned by a different provider.
fn catalog_card_for_provider(model: &str, provider: &str) -> Option<PriceCard> {
    let t = catalog_prices::table();
    let bare = model.strip_prefix(provider)?.strip_prefix('/')?;
    let (input, output, cache_read) = *t
        .get(&(provider, model))
        .or_else(|| t.get(&(provider, bare)))?;
    Some(PriceCard {
        input_per_mtok: input,
        output_per_mtok: output,
        cache_read_per_mtok: cache_read.unwrap_or(input),
        cache_write_per_mtok: input,
        long_context: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-10-08 official-page regression cases. Each corrected hand card has
    // its own assertion so a source change identifies the affected model.
    #[test]
    fn sonnet_5_5_cache_read_is_five_percent() {
        assert!(approx(
            price_card("claude-sonnet-5-5").unwrap().cache_read_per_mtok,
            0.10
        ));
    }

    #[test]
    fn haiku_5_5_has_its_100k_context_tier() {
        let c = price_card("claude-haiku-5-5").unwrap();
        assert!(approx(c.input_per_mtok, 0.10) && approx(c.output_per_mtok, 0.50));
        let long = c.long_context.unwrap();
        assert_eq!(long.threshold_tokens, 100_000);
        assert!(approx(long.input_mult, 5.0) && approx(long.output_mult, 5.0));
    }

    #[test]
    fn grok_4_3_has_a_200k_context_tier() {
        let c = price_card("grok-4.3").unwrap();
        let long = c.long_context.unwrap();
        assert_eq!(long.threshold_tokens, 199_999);
        assert!(approx(long.input_mult, 2.0) && approx(long.output_mult, 2.0));
    }

    #[test]
    fn grok_build_has_a_200k_context_tier() {
        let c = price_card("grok-build-0.1").unwrap();
        let long = c.long_context.unwrap();
        assert_eq!(long.threshold_tokens, 199_999);
        assert!(approx(long.input_mult, 2.0) && approx(long.output_mult, 2.0));
    }

    #[test]
    fn gpt_6_sol_has_272k_context_and_cache_write_prices() {
        let c = price_card("gpt-6-sol").unwrap();
        assert!(approx(c.cache_write_per_mtok, 2.5));
        assert_eq!(c.long_context.unwrap().threshold_tokens, 272_000);
    }

    #[test]
    fn gpt_5_6_sol_has_a_verified_standard_card() {
        let c = price_card("gpt-5.6-sol").unwrap();
        assert!(approx(c.input_per_mtok, 4.0) && approx(c.output_per_mtok, 20.0));
        assert!(approx(c.cache_read_per_mtok, 0.4) && approx(c.cache_write_per_mtok, 5.0));
        assert_eq!(c.long_context.unwrap().threshold_tokens, 272_000);
        assert!(approx(price_card("gpt-5.6").unwrap().input_per_mtok, 4.0));
    }

    #[test]
    fn gpt_5_6_terra_has_a_verified_standard_card() {
        let c = price_card("gpt-5.6-terra").unwrap();
        assert!(approx(c.input_per_mtok, 2.0) && approx(c.output_per_mtok, 12.0));
        assert!(approx(c.cache_read_per_mtok, 0.2) && approx(c.cache_write_per_mtok, 2.5));
        assert_eq!(c.long_context.unwrap().threshold_tokens, 272_000);
    }

    #[test]
    fn gpt_5_6_luna_has_a_verified_standard_card() {
        let c = price_card("gpt-5.6-luna").unwrap();
        assert!(approx(c.input_per_mtok, 0.2) && approx(c.output_per_mtok, 1.2));
        assert!(approx(c.cache_read_per_mtok, 0.02) && approx(c.cache_write_per_mtok, 0.25));
        assert_eq!(c.long_context.unwrap().threshold_tokens, 272_000);
    }

    #[test]
    fn gpt_5_6_cyber_has_a_verified_standard_card() {
        let c = price_card("gpt-5.6-cyber").unwrap();
        assert!(approx(c.input_per_mtok, 12.5) && approx(c.output_per_mtok, 75.0));
        assert!(approx(c.cache_read_per_mtok, 1.25) && approx(c.cache_write_per_mtok, 15.625));
    }

    #[test]
    fn gpt_5_5_has_published_272k_context_tier() {
        let long = price_card("gpt-5.5").unwrap().long_context.unwrap();
        assert_eq!(long.threshold_tokens, 272_000);
        assert!(approx(long.input_mult, 2.0) && approx(long.output_mult, 1.5));
    }

    #[test]
    fn kimi_k2_6_has_a_first_party_card() {
        let c = price_card("kimi-k2.6").unwrap();
        assert!(approx(c.input_per_mtok, 0.95) && approx(c.output_per_mtok, 4.0));
        assert!(approx(c.cache_read_per_mtok, 0.16));
    }

    #[test]
    fn kimi_k2_7_code_has_a_first_party_card() {
        let c = price_card("kimi-k2.7-code").unwrap();
        assert!(approx(c.input_per_mtok, 0.95) && approx(c.output_per_mtok, 4.0));
        assert!(approx(c.cache_read_per_mtok, 0.19));
    }

    #[test]
    fn glm_5_3_flashx_has_a_first_party_card() {
        let c = price_card("glm-5.3-flashx").unwrap();
        assert!(approx(c.input_per_mtok, 0.37) && approx(c.output_per_mtok, 1.25));
        assert!(approx(c.cache_read_per_mtok, 0.075));
    }

    #[test]
    fn gemini_3_5_flash_lite_does_not_take_flash_price() {
        let c = price_card("gemini-3.5-flash-lite").unwrap();
        assert!(approx(c.input_per_mtok, 0.30) && approx(c.output_per_mtok, 2.50));
        assert!(approx(c.cache_read_per_mtok, 0.03));
    }

    #[test]
    fn gpt_6_family_has_published_cache_write_rates() {
        for (model, expected) in [
            ("gpt-6-astra", 12.5),
            ("gpt-6.1-sol", 2.5),
            ("gpt-6-luna", 0.125),
        ] {
            assert!(
                approx(price_card(model).unwrap().cache_write_per_mtok, expected),
                "{model}"
            );
        }
    }

    #[test]
    fn kimi_k3_cache_write_uses_published_rate() {
        assert!(approx(
            price_card("kimi-k3").unwrap().cache_write_per_mtok,
            3.0
        ));
    }

    #[test]
    fn qwen_3_7_plus_long_context_uses_published_tier() {
        let long = price_card("qwen3.7-plus").unwrap().long_context.unwrap();
        assert_eq!(long.threshold_tokens, 256_000);
        assert!(approx(long.input_mult, 3.0) && approx(long.output_mult, 3.0));
    }

    #[test]
    fn qwen_cards_record_implicit_cache_hit_rates() {
        for (model, expected) in [
            ("qwen3.8-max", 0.40),
            ("qwen3.7-plus", 0.08),
            ("qwen3.8-flash", 0.03),
        ] {
            assert!(
                approx(price_card(model).unwrap().cache_read_per_mtok, expected),
                "{model}"
            );
        }
    }

    #[test]
    fn gpt_4o_cards_record_published_cache_hit_rates() {
        for (model, expected) in [("gpt-4o", 1.25), ("gpt-4o-mini", 0.075)] {
            assert!(
                approx(price_card(model).unwrap().cache_read_per_mtok, expected),
                "{model}"
            );
        }
    }

    #[test]
    fn gemini_2_5_pro_has_published_long_context_and_cache_rates() {
        let c = price_card("gemini-2.5-pro").unwrap();
        assert!(approx(c.cache_read_per_mtok, 0.125));
        let long = c.long_context.unwrap();
        assert_eq!(long.threshold_tokens, 200_000);
        assert!(approx(long.input_mult, 2.0) && approx(long.output_mult, 1.5));
    }

    #[test]
    fn gemini_flash_cards_record_published_cache_hit_rates() {
        for (model, expected) in [
            ("gemini-3-flash-preview", 0.05),
            ("gemini-2.5-flash", 0.03),
            ("gemini-2.5-flash-lite", 0.01),
        ] {
            assert!(
                approx(price_card(model).unwrap().cache_read_per_mtok, expected),
                "{model}"
            );
        }
    }

    #[test]
    fn reseller_claude_price_comes_from_its_own_catalog_row() {
        let model = "bedrock/au.anthropic.claude-haiku-5-5";
        assert!(price_card(model).is_none());
        assert!(approx(catalog_card(model).unwrap().input_per_mtok, 0.11));
    }

    #[test]
    fn operator_alias_named_like_a_first_party_model_uses_the_configured_provider() {
        let reseller = crate::server::config::ModelAlias {
            provider_id: "openrouter".to_string(),
            upstream_model: "openai/gpt-5.6-sol".to_string(),
        };
        let priced = price_model("gpt-5.6-sol", Some(&reseller));
        assert_eq!(priced.as_ref(), "openrouter/openai/gpt-5.6-sol");
        assert!(price_card(priced.as_ref()).is_none());
        assert!(approx(
            catalog_card(priced.as_ref()).unwrap().input_per_mtok,
            2.0
        ));
        let million = usage(1_000_000, 0, None, None);
        assert!(approx(cost_usd("gpt-5.6-sol", &million).unwrap(), 8.0));
        assert!(approx(
            cost_usd_for_routed_model("gpt-5.6-sol", Some(&reseller), &million).unwrap(),
            2.0
        ));

        let first_party = crate::server::config::ModelAlias {
            provider_id: "openai".to_string(),
            upstream_model: "gpt-5.6-sol".to_string(),
        };
        let priced = price_model("custom-model", Some(&first_party));
        assert_eq!(priced.as_ref(), "openai/gpt-5.6-sol");
        assert!(approx(
            price_card(priced.as_ref()).unwrap().input_per_mtok,
            4.0
        ));
        assert!(approx(
            cost_usd_for_routed_model("custom-model", Some(&first_party), &million).unwrap(),
            8.0
        ));
        let unpriced_reseller = crate::server::config::ModelAlias {
            provider_id: "openrouter".to_string(),
            upstream_model: "gpt-5.6-sol".to_string(),
        };
        assert!(
            cost_usd_for_routed_model("gpt-5.6-sol", Some(&unpriced_reseller), &million).is_none()
        );
        assert_eq!(price_model("gpt-5.6-sol", None).as_ref(), "gpt-5.6-sol");
    }

    #[test]
    fn modality_variants_do_not_take_text_cards() {
        for model in ["gpt-4o-mini-tts", "gemini-3.8-flash-tts"] {
            assert!(price_card(model).is_none(), "{model}");
        }
    }

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

    // ── GWY-42: the generated catalog table ─────────────────────────────────

    /// The founder-verified cards must be untouched by the catalog. If the
    /// catalog could override one, every hand-checked rate in this file would be
    /// silently replaced by a third party's number on the next regeneration.
    #[test]
    fn hand_verified_cards_still_win_over_the_catalog() {
        // Same expectation as `sonnet_input_output_cost`, asserted here as the
        // precedence claim rather than as arithmetic.
        let c = cost_usd("claude-sonnet-4-6", &usage(1000, 500, None, None)).unwrap();
        assert!(
            approx(c, 0.0105),
            "verified Sonnet card must still price it: got {c}"
        );
        // And the verified card is what `price_card` returns, with the catalog
        // never consulted.
        assert!(price_card("claude-sonnet-4-6").is_some());
    }

    /// The coverage hole this table was built to close. Every one of these
    /// returned `None` before, and `None` reached the dashboard as $0.00.
    #[test]
    fn models_that_used_to_be_unpriced_now_price() {
        let u = usage(1_000_000, 1_000_000, None, None);
        // 2026-09-06: the catalog was regenerated from models.dev (to pick up
        // `claude-fable-5-1`, the model Claude Code sessions default to — PLT-46)
        // and models.dev had DROPPED its `deepseek/deepseek-chat` and
        // `deepseek/deepseek-reasoner` rows, so those two went unpriced (B-351).
        // 2026-09-07: they price again — from a hand card read off DeepSeek's
        // own pricing page, not a guess (see `price_card`).
        for m in [
            "gpt-5",
            "gpt-4.1",
            "o3-mini",
            "grok-4.6",
            "claude-fable-5-1",
            "deepseek-chat",
            "deepseek-reasoner",
        ] {
            let c = cost_usd(m, &u);
            assert!(
                c.is_some_and(|v| v > 0.0),
                "`{m}` must now have a price; it is one of the models whose \
                 missing card summed as $0.00 into the spend tile"
            );
        }
    }

    /// Widening coverage must not overturn a standing honesty policy. The
    /// generator drops every `*-latest` row for the same reason
    /// `floating_latest_aliases_are_unpriced` exists: the alias points at a
    /// different model over time, so a rate recorded against it is a rate for a
    /// model we cannot name.
    #[test]
    fn the_catalog_does_not_reintroduce_floating_alias_prices() {
        for m in [
            "mistral-large-latest",
            "gemini-flash-latest",
            "codestral-latest",
        ] {
            assert_eq!(
                cost_usd(m, &usage(1000, 1000, None, None)),
                None,
                "`{m}` is a moving target and must stay unpriced"
            );
        }
    }

    /// The honest half. A model nobody sells has no price — and `None` must
    /// never soften into `Some(0.0)`, because zero is a claim.
    #[test]
    fn an_unknown_model_is_still_none_never_zero() {
        for m in ["totally-made-up-model-9000", "", "not-a-provider/whatever"] {
            assert_eq!(
                cost_usd(m, &usage(1000, 1000, None, None)),
                None,
                "`{m}` must be unpriced, not free"
            );
        }
    }

    /// A model routed through a `provider/` prefix prices from THAT provider's
    /// row. The prefix is ours and never appears on a vendor's price list, so
    /// the lookup has to strip it — and if it stripped it too eagerly it would
    /// price a Groq request at OpenAI's rate.
    #[test]
    fn a_prefixed_model_prices_from_its_own_provider() {
        let u = usage(1_000_000, 0, None, None);
        let together = cost_usd("together/moonshotai/Kimi-K2-Instruct", &u);
        if let Some(v) = together {
            assert!(v > 0.0, "a priced Together model must cost something");
        }
        // The property that matters even when a specific row is absent: an
        // unroutable model is unpriced, because we do not know who sold it.
        assert_eq!(cost_usd("nosuchprovider/some-model", &u), None);
    }

    /// Cache rates are conservative by construction: an unknown cache discount
    /// is charged at the full input rate. Under-charging is the direction that
    /// silently overspends a budget.
    #[test]
    fn an_unknown_cache_discount_is_charged_at_the_input_rate_not_free() {
        let with_cache = cost_usd("gpt-5", &usage(0, 0, Some(1_000_000), None));
        assert!(
            with_cache.is_some_and(|v| v > 0.0),
            "cache-read tokens must never be free just because no discount is published"
        );
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
        assert!(approx(opus, 0.03), "opus got {opus}"); // (5000+25000)/1e6
        assert!(opus > sonnet);
    }

    /// B-350. Every Opus a customer can call today (4.5 … 5) is 5/25; only the
    /// retired Opus 4 / 4.1 and Claude 3 Opus are 15/75. Until 2026-09-07 one
    /// card priced them all at 15/75, and the models.dev refresh exposed it.
    /// Prices: platform.claude.com/docs/en/about-claude/pricing, 2026-09-07.
    #[test]
    fn opus_price_is_version_aware() {
        let u = usage(1_000_000, 1_000_000, None, None);
        for m in [
            "claude-opus-4-5",
            "claude-opus-4-5-20251101",
            "anthropic.claude-opus-4-5-20251101-v1:0", // Bedrock id
            "claude-opus-4-6",
            "claude-opus-4-7",
            "claude-opus-4-8",
            "claude-opus-5",
        ] {
            let c = cost_usd(m, &u).unwrap();
            assert!(approx(c, 30.0), "`{m}` must price 5/25, got {c}");
        }
        for m in [
            "claude-opus-4-1",
            "claude-opus-4-20250514",
            "claude-3-opus-20240229",
        ] {
            let c = cost_usd(m, &u).unwrap();
            assert!(approx(c, 90.0), "`{m}` must price 15/75, got {c}");
        }
        // Cache tiers follow the base rate: 0.1× read, 1.25× write.
        let cached = cost_usd(
            "claude-opus-4-8",
            &usage(0, 0, Some(1_000_000), Some(1_000_000)),
        )
        .unwrap();
        assert!(
            approx(cached, 0.5 + 6.25),
            "opus 4.8 cache tiers got {cached}"
        );
    }

    /// Fable / Mythos 5 and 5.1 are 10/50 with a 12.50 cache write; ONLY the 5.1
    /// generation reads cache at 0.025× (0.25), Fable 5 reads at 0.1× (1.00).
    #[test]
    fn fable_and_mythos_cards_including_the_5_1_cache_read() {
        let u = usage(1_000_000, 1_000_000, Some(1_000_000), Some(1_000_000));
        let f51 = cost_usd("claude-fable-5-1", &u).unwrap();
        assert!(
            approx(f51, 10.0 + 50.0 + 0.25 + 12.5),
            "fable 5.1 got {f51}"
        );
        let f5 = cost_usd("claude-fable-5", &u).unwrap();
        assert!(approx(f5, 10.0 + 50.0 + 1.0 + 12.5), "fable 5 got {f5}");
        let m51 = cost_usd("claude-mythos-5-1", &u).unwrap();
        assert!(
            approx(m51, f51),
            "mythos 5.1 must equal fable 5.1, got {m51}"
        );
        // The hand card, not the catalog, answers — so a stale catalog row
        // cannot move this number.
        assert!(price_card("claude-fable-5-1").is_some());
    }

    /// Sonnet 5 is 2/10 (introductory pricing made permanent); Sonnet 4.x is
    /// 3/15. The `sonnet-5` substring must not capture `sonnet-4-5`.
    #[test]
    fn sonnet_5_is_2_10_and_does_not_capture_sonnet_4_5() {
        let u = usage(1_000_000, 1_000_000, None, None);
        assert!(approx(cost_usd("claude-sonnet-5", &u).unwrap(), 12.0));
        assert!(approx(cost_usd("claude-sonnet-4-5", &u).unwrap(), 18.0));
        assert!(approx(
            cost_usd("claude-sonnet-4-5-20250929", &u).unwrap(),
            18.0
        ));
        assert!(approx(cost_usd("claude-sonnet-4-6", &u).unwrap(), 18.0));
        assert!(approx(
            cost_usd("claude-3-5-sonnet-20241022", &u).unwrap(),
            18.0
        ));
    }

    /// Haiku 3.5 (retired) is 0.80/4; Haiku 4.5 is 1/5.
    #[test]
    fn haiku_3_5_is_priced_below_haiku_4_5() {
        let u = usage(1_000_000, 1_000_000, None, None);
        assert!(approx(
            cost_usd("claude-3-5-haiku-20241022", &u).unwrap(),
            4.8
        ));
        assert!(approx(
            cost_usd("claude-haiku-4-5-20251001", &u).unwrap(),
            6.0
        ));
    }

    /// B-351 / OG-05. DeepSeek first-party ids price at DeepSeek's own PEAK list
    /// rates (api-docs.deepseek.com/quick_start/pricing, verified 2026-10-01):
    /// `deepseek-flash` 0.30/1.20, `deepseek-v4-pro` 1.32/3.96 — the conservative
    /// side for budget enforcement (see the card). The legacy `deepseek-chat` /
    /// `deepseek-reasoner` names point at V4-Flash and price identically. The
    /// models.dev row for `deepseek/deepseek-v4-flash` still says 0.14/0.28, which
    /// is exactly why the hand card must win.
    #[test]
    fn deepseek_first_party_prices_from_deepseeks_own_page_not_the_stale_catalog() {
        let u = usage(1_000_000, 1_000_000, None, None);
        for m in [
            "deepseek-flash",
            "deepseek-v4-flash",
            "deepseek/deepseek-v4-flash",
            "deepseek-chat",
            "deepseek-reasoner",
        ] {
            let c = cost_usd(m, &u).unwrap();
            assert!(
                approx(c, 0.30 + 1.20),
                "`{m}` must price at Flash PEAK 0.30/1.20, got {c}"
            );
        }
        let pro = cost_usd("deepseek-v4-pro", &u).unwrap();
        assert!(approx(pro, 1.32 + 3.96), "v4-pro got {pro}");
        // The stale catalog value must NOT be what answers.
        assert!(price_card("deepseek-v4-flash").is_some());
        assert!(!approx(
            cost_usd("deepseek-v4-flash", &u).unwrap(),
            0.14 + 0.28
        ));
        // Cache-hit read rates are on the cards (0.006 / 0.044, peak).
        let c = cost_usd("deepseek-flash", &usage(0, 0, Some(1_000_000), None)).unwrap();
        assert!(approx(c, 0.006), "flash cache read got {c}");
        let c = cost_usd("deepseek-v4-pro", &usage(0, 0, Some(1_000_000), None)).unwrap();
        assert!(approx(c, 0.044), "v4-pro cache read got {c}");
    }

    /// The DeepSeek hand card is scoped to the FIRST-PARTY route. A reseller's
    /// DeepSeek model (`groq/deepseek-r1-…`, `abacus/…`) is that reseller's price,
    /// which the catalog carries — the hand card must not shadow it.
    #[test]
    fn deepseek_hand_card_does_not_shadow_reseller_routes() {
        assert!(price_card("groq/deepseek-r1-distill-llama-70b").is_none());
        assert!(price_card("abacus/deepseek-ai/DeepSeek-V4-Flash").is_none());
        // A first-party id DeepSeek no longer lists falls through to the catalog
        // rather than getting a guessed V4 price.
        assert!(price_card("deepseek-r1").is_none());
    }

    #[test]
    fn haiku_cost() {
        // (1000*1 + 1000*5) / 1e6 = 0.006
        let c = cost_usd("claude-haiku-4-5", &usage(1000, 1000, None, None)).unwrap();
        assert!(approx(c, 0.006), "got {c}");
    }

    /// The models a NEW Google key can actually call are gemini-3.x — the
    /// 2.5 cards shipped in `46e2043` cover models that 404 (deprecated for new
    /// users) or 429 (billing-gated). This is the live capability matrix, encoded:
    /// if these ever return None again, gemini traffic silently bills $0.
    #[test]
    fn gemini_3x_models_are_priced_from_verified_list_rates() {
        // ai.google.dev/gemini-api/docs/pricing, verified 2026-07-17.
        // (in_per_mtok, out_per_mtok) — output includes thinking tokens per Google.
        for (model, inp, out) in [
            ("gemini-3-flash-preview", 0.50_f64, 3.00_f64),
            ("gemini-3.8-flash", 0.75, 3.75),
            ("gemini-3.5-flash", 1.50, 9.00),
            ("gemini-3.1-flash-lite", 0.25, 1.50),
            ("gemini-3.1-pro-preview", 2.00, 12.00),
        ] {
            // 100k each: under every long-context threshold, so the FLAT price.
            let c = cost_usd(model, &usage(100_000, 100_000, None, None))
                .unwrap_or_else(|| panic!("{model} MUST be priced — unpriced gemini bills $0"));
            let want = (inp + out) / 10.0;
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
        // Gemini-2.5-pro base tier (1.25/10.0): (677*1.25 + 575*10)/1e6.
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

    // ── OG-05: verified frontier cards (list prices verified 2026-10-08) ──────

    /// Cost of 50k input + 50k output + 50k cache-read, times 20 = the per-Mtok
    /// sum. A 100K prompt (50k + 50k cached) keeps every prompt UNDER the
    /// long-context thresholds (200K and 272K), so this reads the FLAT list price.
    fn mtok_cost(model: &str) -> f64 {
        cost_usd(model, &usage(50_000, 50_000, Some(50_000), None))
            .map(|c| c * 20.0)
            .unwrap_or_else(|| panic!("`{model}` must have a verified card"))
    }

    /// Each card equals its documented (input, cached-input, output) list price.
    /// Sources: developers.openai.com/api/docs/pricing,
    /// platform.claude.com/docs/en/about-claude/pricing (cache WRITE excluded),
    /// ai.google.dev/gemini-api/docs/pricing, docs.x.ai/developers/pricing,
    /// api-docs.deepseek.com/quick_start/pricing, platform.kimi.ai,
    /// docs.z.ai/guides/overview/pricing, alibabacloud.com/help/en/model-studio/model-pricing.
    #[test]
    fn og05_every_verified_card_equals_its_documented_list_price() {
        // (model, input, cached read, output) USD per Mtok.
        let cards: &[(&str, f64, f64, f64)] = &[
            ("gpt-6-astra", 10.0, 1.0, 50.0),
            ("gpt-6.1-sol", 2.0, 0.10, 10.0),
            ("gpt-6-sol", 2.0, 0.20, 10.0),
            ("gpt-6-luna", 0.10, 0.01, 0.50),
            ("gpt-5.6-sol", 4.0, 0.40, 20.0),
            ("gpt-5.6-terra", 2.0, 0.20, 12.0),
            ("gpt-5.6-luna", 0.20, 0.02, 1.20),
            ("gpt-5.6-cyber", 12.50, 1.25, 75.0),
            ("gpt-5.5", 5.0, 0.5, 30.0),
            ("gpt-5.5-pro", 30.0, 0.0, 180.0),
            ("gpt-5.3-codex", 1.75, 0.175, 14.0),
            ("claude-fable-5-1", 10.0, 0.25, 50.0),
            ("claude-opus-5-5", 4.0, 0.20, 20.0),
            ("claude-sonnet-5-5", 2.0, 0.10, 10.0),
            ("claude-haiku-5-5", 0.10, 0.01, 0.50),
            ("claude-haiku-4-5", 1.0, 0.10, 5.0),
            ("gemini-3.1-pro-preview", 2.0, 0.20, 12.0),
            ("gemini-3.8-flash", 0.75, 0.075, 3.75),
            ("gemini-3.5-flash", 1.50, 0.15, 9.00),
            ("gemini-3.5-flash-lite", 0.30, 0.03, 2.50),
            ("gemini-3.1-flash-lite", 0.25, 0.025, 1.50),
            ("grok-4.7", 2.0, 0.50, 6.0),
            ("grok-4.3", 1.25, 0.20, 2.5),
            ("grok-build-0.1", 1.0, 0.20, 2.0),
            ("deepseek-flash", 0.30, 0.006, 1.20), // PEAK (B-351: budget-safe side)
            ("deepseek-v4-pro", 1.32, 0.044, 3.96), // PEAK
            ("kimi-k3", 3.0, 0.30, 15.0),
            ("kimi-k2.7-code", 0.95, 0.19, 4.0),
            ("kimi-k2.6", 0.95, 0.16, 4.0),
            ("glm-5.3", 1.4, 0.26, 4.4),
            ("glm-5.3-flash", 0.15, 0.03, 0.50),
            ("glm-5.3-flashx", 0.37, 0.075, 1.25),
            ("qwen3.8-max", 2.0, 0.40, 6.0),
            ("qwen3.7-plus", 0.4, 0.08, 1.6),
            ("qwen3.8-flash", 0.15, 0.03, 0.47),
        ];
        for (model, i, c, o) in cards {
            let got = mtok_cost(model);
            assert!(
                approx(got, i + c + o),
                "`{model}`: got {got}, want {} (in {i} + cache {c} + out {o})",
                i + c + o
            );
            // Each is a HAND card (price_card), never the generated catalog.
            assert!(price_card(model).is_some(), "`{model}` must be a hand card");
        }
    }

    /// Opus 5.5 is 4/20 and MUST NOT be captured by the older `opus-5` arm
    /// (5/25), whose substring also matches `opus-5-5`; plain Opus 5 is
    /// unchanged. Cache write is 1.25x input.
    #[test]
    fn og05_opus_5_5_is_4_20_and_opus_5_stays_5_25() {
        let u = usage(1_000_000, 1_000_000, None, None);
        assert!(approx(cost_usd("claude-opus-5-5", &u).unwrap(), 24.0));
        assert!(approx(cost_usd("claude-opus-5", &u).unwrap(), 30.0));
        let w = cost_usd("claude-opus-5-5", &usage(0, 0, None, Some(1_000_000))).unwrap();
        assert!(approx(w, 5.0), "opus 5.5 cache write got {w}");
    }

    /// A SIBLING must never take another model's price: `gpt-5.5-pro` is not
    /// `gpt-5.5`, `gpt-5.5-mini` is neither (so it is NOT priced by a verified
    /// card), and a dated snapshot of a verified model still prices.
    #[test]
    fn og05_siblings_do_not_inherit_a_verified_card() {
        let u = usage(1_000_000, 0, None, None);
        assert!(approx(cost_usd("gpt-5.5", &u).unwrap(), 10.0));
        assert!(approx(cost_usd("gpt-5.5-pro", &u).unwrap(), 30.0));
        assert!(price_card("gpt-5.5-mini").is_none());
        assert!(price_card("gpt-6-astra-mini").is_none());
        assert!(price_card("glm-5.3-air").is_none());
        assert!(price_card("kimi-k3-turbo").is_none());
        assert!(price_card("gemini-3.8-flash-lite").is_none());
        // Dated snapshot of a verified model.
        assert!(approx(cost_usd("gpt-5.5-2026-10-01", &u).unwrap(), 10.0));
        assert!(approx(cost_usd("openai/gpt-5.5", &u).unwrap(), 10.0));
    }

    /// The pricing-source guard: a verified first-party card is NEVER shadowed by
    /// a reseller's row, and a RESELLER route is never priced by the first-party
    /// card — `openrouter/openai/gpt-5.5` and `together/moonshotai/kimi-k3` skip
    /// the hand cards (they price from their own reseller rows or not at all).
    #[test]
    fn og05_reseller_route_does_not_use_the_first_party_card_and_vice_versa() {
        for m in [
            "openrouter/openai/gpt-5.5",
            "openrouter/openai/gpt-6-astra",
            "together/moonshotai/kimi-k3",
            "groq/qwen3.8-max",
            "openrouter/x-ai/grok-4.7",
        ] {
            assert!(
                price_card(m).is_none(),
                "`{m}` is a reseller route: it must NOT take the first-party hand card"
            );
        }
        // And the first-party id always answers from the hand card.
        for m in ["gpt-6-astra", "kimi-k3", "qwen3.8-max", "grok-4.7"] {
            assert!(price_card(m).is_some(), "`{m}` must be a hand card");
        }
    }

    /// Long-context tiers. OpenAI above 272K: 2x input, 1.5x output; Gemini 3.1
    /// Pro above 200K: 4/18; xAI Grok 4.7 at or above 200K: 4/1.00/12. At or
    /// below the threshold the flat price applies.
    #[test]
    fn og05_long_context_tiers_apply_above_the_threshold_only() {
        // gpt-6-astra: 272,000 tokens is NOT above the threshold; 272,001 is.
        let at = cost_usd("gpt-6-astra", &usage(272_000, 1_000_000, None, None)).unwrap();
        assert!(
            approx(at, 272_000.0 * 10.0 / 1e6 + 50.0),
            "at-threshold {at}"
        );
        let over = cost_usd("gpt-6-astra", &usage(272_001, 1_000_000, None, None)).unwrap();
        assert!(
            approx(over, 272_001.0 * 20.0 / 1e6 + 75.0),
            "above-threshold {over}"
        );
        // The cached prefix counts toward the prompt size.
        let cached = cost_usd("gpt-6.1-sol", &usage(100_000, 0, Some(200_000), None)).unwrap();
        assert!(
            approx(cached, (100_000.0 * 2.0 + 200_000.0 * 0.10) * 2.0 / 1e6),
            "cached prefix must trigger the tier: {cached}"
        );
        // GPT-6 Sol now has the same >272K tier as the other GPT-6 cards.
        let sol = cost_usd("gpt-6-sol", &usage(500_000, 0, None, None)).unwrap();
        assert!(approx(sol, 2.0), "gpt-6-sol long context: {sol}");
        // Gemini 3.1 Pro: 4/18 above 200K.
        let g = cost_usd(
            "gemini-3.1-pro-preview",
            &usage(1_000_000, 1_000_000, None, None),
        )
        .unwrap();
        assert!(approx(g, 4.0 + 18.0), "gemini 3.1 pro >200k got {g}");
        let g_low = cost_usd(
            "gemini-3.1-pro-preview",
            &usage(200_000, 1_000_000, None, None),
        )
        .unwrap();
        assert!(
            approx(g_low, 0.4 + 12.0),
            "gemini 3.1 pro <=200k got {g_low}"
        );
        // Grok 4.7: at or above 200,000 -> 4 / 12.
        let x = cost_usd("grok-4.7", &usage(200_000, 1_000_000, None, None)).unwrap();
        assert!(approx(x, 0.8 + 12.0), "grok 4.7 at 200k got {x}");
        let x_low = cost_usd("grok-4.7", &usage(199_999, 1_000_000, None, None)).unwrap();
        assert!(
            approx(x_low, 199_999.0 * 2.0 / 1e6 + 6.0),
            "grok 4.7 below {x_low}"
        );
    }

    /// The honest half: an unknown frontier-looking id is `None`, never zero.
    #[test]
    fn og05_unknown_frontier_ids_stay_unpriced() {
        for m in [
            "gpt-9-hypothetical",
            "kimi-k9",
            "glm-9",
            "qwen9.9-max",
            "grok-9",
        ] {
            assert_eq!(cost_usd(m, &usage(1000, 1000, None, None)), None, "`{m}`");
        }
    }
}
