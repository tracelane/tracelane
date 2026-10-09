//! `OG-06` §3.4 — the per-UNIT price table (images, speech characters, transcription
//! seconds, rerank search units), read once from `crates/gateway/unit_prices.v1.json`.
//!
//! Token prices live in `pricing.rs`; the media routes bill in other units. Same
//! contract as there (ADR-021/055): **an unknown model is `None`, never `0`**. A
//! request that is not priced is counted as unpriced (B-350), and the table
//! deliberately ships without image or rerank rows because no vendor price page
//! states a per-image or per-search number the gateway can quote.
//!
//! **Fail direction.** A table that does not parse prices NOTHING (every lookup is
//! `None`) — the unit tests make a broken edit a red build, not a runtime surprise.
//!
//! Callers: `media_routes` (per-request unit cost), `files_batches` (the batch
//! multiplier on a completed batch's token usage).

use std::sync::OnceLock;

use serde_json::Value;

/// The units a media route can record. The JSON's `units` list must name exactly these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unit {
    Images,
    SpeechCharacters,
    TranscriptionSeconds,
    RerankSearchUnits,
}

impl Unit {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Images => "images_generated",
            Self::SpeechCharacters => "speech_characters",
            Self::TranscriptionSeconds => "transcription_seconds",
            Self::RerankSearchUnits => "rerank_search_units",
        }
    }
}

#[derive(Debug)]
struct Entry {
    provider: String,
    model: String,
    unit: String,
    qualifier: Option<String>,
    usd_per_unit: f64,
}

#[derive(Debug)]
struct Table {
    entries: Vec<Entry>,
    batch_multiplier: f64,
}

static TABLE: OnceLock<Option<Table>> = OnceLock::new();

fn table() -> Option<&'static Table> {
    TABLE
        .get_or_init(|| parse(include_str!("../unit_prices.v1.json")))
        .as_ref()
}

fn parse(raw: &str) -> Option<Table> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let known: Vec<&str> = [
        Unit::Images,
        Unit::SpeechCharacters,
        Unit::TranscriptionSeconds,
        Unit::RerankSearchUnits,
    ]
    .iter()
    .map(|u| u.as_str())
    .collect();
    let declared: Vec<&str> = v
        .get("units")?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()?;
    if declared != known {
        return None;
    }
    let mut entries = Vec::new();
    for e in v.get("entries")?.as_array()? {
        let unit = e.get("unit")?.as_str()?;
        let price = e.get("usd_per_unit")?.as_f64()?;
        // A negative, NaN or missing price is a broken edit: refuse the whole table.
        if !known.contains(&unit) || !price.is_finite() || price < 0.0 {
            return None;
        }
        // Every row names its vendor source — a price nobody can trace is not a price.
        if e.get("source")?.as_str()?.is_empty() {
            return None;
        }
        entries.push(Entry {
            provider: e.get("provider")?.as_str()?.to_ascii_lowercase(),
            model: e.get("model")?.as_str()?.to_ascii_lowercase(),
            unit: unit.to_owned(),
            qualifier: e
                .get("qualifier")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase),
            usd_per_unit: price,
        });
    }
    let batch_multiplier = v.pointer("/batch/price_multiplier")?.as_f64()?;
    if !(batch_multiplier.is_finite() && batch_multiplier > 0.0 && batch_multiplier <= 1.0) {
        return None;
    }
    Some(Table {
        entries,
        batch_multiplier,
    })
}

/// Does `model` name `name` exactly, or a DATED snapshot of it (`name-2026-10-01`)?
/// `tts-1` must not capture `tts-1-hd`, which is another model at another price.
fn names_model(model: &str, name: &str) -> bool {
    model == name
        || model
            .strip_prefix(name)
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
}

/// USD for `quantity` of `unit` on `(provider, model)`; `qualifier` is an optional
/// size/quality string a row may be specific to. `None` when no row prices it — which
/// the caller records as UNPRICED, never as zero.
#[must_use]
pub(crate) fn cost_usd(
    provider: &str,
    model: &str,
    unit: Unit,
    qualifier: Option<&str>,
    quantity: f64,
) -> Option<f64> {
    if !quantity.is_finite() || quantity < 0.0 {
        return None;
    }
    let t = table()?;
    let provider = provider.to_ascii_lowercase();
    let model = model.to_ascii_lowercase();
    let model = model
        .strip_prefix(&format!("{provider}/"))
        .unwrap_or(&model);
    let qualifier = qualifier.map(str::to_ascii_lowercase);
    // A qualified row beats an unqualified one for the same model.
    let hit = t
        .entries
        .iter()
        .filter(|e| {
            e.provider == provider && e.unit == unit.as_str() && names_model(model, &e.model)
        })
        .filter(|e| e.qualifier.is_none() || e.qualifier == qualifier)
        .max_by_key(|e| (e.model.len(), e.qualifier.is_some()))?;
    Some(hit.usd_per_unit * quantity)
}

/// `H2`: does ANY row price `unit` on `(provider, model)` (whatever its qualifier)?
/// `false` on an unreadable table — the caller then treats the call as unpriced.
#[must_use]
pub(crate) fn has_price(provider: &str, model: &str, unit: Unit) -> bool {
    let Some(t) = table() else {
        return false;
    };
    let provider = provider.to_ascii_lowercase();
    let model = model.to_ascii_lowercase();
    let model = model
        .strip_prefix(&format!("{provider}/"))
        .unwrap_or(&model);
    t.entries
        .iter()
        .any(|e| e.provider == provider && e.unit == unit.as_str() && names_model(model, &e.model))
}

/// The Batch API multiplier on a synchronous list price, or `None` (table unreadable —
/// the caller then records the batch as unpriced rather than guessing 1.0).
#[must_use]
pub(crate) fn batch_price_multiplier() -> Option<f64> {
    table().map(|t| t.batch_multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_parses() {
        assert!(table().is_some(), "unit_prices.v1.json must parse");
    }

    #[test]
    fn a_priced_model_costs_unit_times_rate() {
        let c = cost_usd("openai", "tts-1", Unit::SpeechCharacters, None, 1_000_000.0)
            .expect("tts-1 is priced");
        assert!((c - 15.0).abs() < 1e-9, "{c}");
        let c = cost_usd(
            "openai",
            "whisper-1",
            Unit::TranscriptionSeconds,
            None,
            60.0,
        )
        .expect("whisper-1 is priced");
        assert!((c - 0.006).abs() < 1e-9, "{c}");
        // A dated snapshot resolves to its family; a provider prefix is tolerated.
        assert!(
            cost_usd(
                "openai",
                "openai/tts-1-2026-01-01",
                Unit::SpeechCharacters,
                None,
                1.0
            )
            .is_some()
        );
    }

    #[test]
    fn an_unpriced_model_unit_or_provider_is_none_never_zero() {
        // Images are deliberately unpriced (no vendor per-image number).
        assert_eq!(
            cost_usd(
                "openai",
                "gpt-image-2.5-flare",
                Unit::Images,
                Some("1024x1024"),
                3.0
            ),
            None
        );
        // tts-1 is not tts-1-hd, and neither is a sibling of the other's price.
        let a = cost_usd("openai", "tts-1", Unit::SpeechCharacters, None, 1000.0).expect("a");
        let b = cost_usd("openai", "tts-1-hd", Unit::SpeechCharacters, None, 1000.0).expect("b");
        assert!(b > a);
        // Wrong unit for a priced model, wrong provider, unknown model.
        assert_eq!(cost_usd("openai", "tts-1", Unit::Images, None, 1.0), None);
        assert_eq!(
            cost_usd("groq", "tts-1", Unit::SpeechCharacters, None, 1.0),
            None
        );
        assert_eq!(
            cost_usd("openai", "tts-9", Unit::SpeechCharacters, None, 1.0),
            None
        );
        // A nonsense quantity is not priced.
        assert_eq!(
            cost_usd("openai", "tts-1", Unit::SpeechCharacters, None, -1.0),
            None
        );
        assert_eq!(
            cost_usd("openai", "tts-1", Unit::SpeechCharacters, None, f64::NAN),
            None
        );
    }

    #[test]
    fn a_broken_table_prices_nothing() {
        assert!(parse("not json").is_none());
        let neg = r#"{"units":["images_generated","speech_characters","transcription_seconds","rerank_search_units"],
            "entries":[{"provider":"p","model":"m","unit":"images_generated","usd_per_unit":-1,"source":"s"}],
            "batch":{"price_multiplier":0.5}}"#;
        assert!(parse(neg).is_none(), "a negative price refuses the table");
        let no_source = r#"{"units":["images_generated","speech_characters","transcription_seconds","rerank_search_units"],
            "entries":[{"provider":"p","model":"m","unit":"images_generated","usd_per_unit":1,"source":""}],
            "batch":{"price_multiplier":0.5}}"#;
        assert!(
            parse(no_source).is_none(),
            "an untraceable price refuses the table"
        );
        let bad_batch = r#"{"units":["images_generated","speech_characters","transcription_seconds","rerank_search_units"],
            "entries":[],"batch":{"price_multiplier":1.5}}"#;
        assert!(
            parse(bad_batch).is_none(),
            "a batch multiplier above 1 is refused"
        );
    }

    #[test]
    fn the_batch_multiplier_is_the_documented_half() {
        assert_eq!(batch_price_multiplier(), Some(0.5));
    }
}
