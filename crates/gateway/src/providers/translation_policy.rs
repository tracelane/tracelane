//! `OG-03` — the request-translation reference table (limits + `reasoning_effort`), read once.
//!
//! The mapping from an OpenAI-style effort word to each native provider's own
//! thinking control lives in `crates/gateway/translation_policy.v1.json`
//! (CLAUDE.md §23: a value a founder ruling or a provider release could change is
//! DATA). The file is embedded with `include_str!` and parsed once, the same shape
//! as `providers.tsv` and `generation_issues.v1.json` in this crate.
//!
//! **Why not a Neon table + the entitlement-cache refresher.** The BILL-01 shape
//! (seeded Postgres table, hand-applied migration, `ArcSwap` refresher) is built for
//! values an operator edits LIVE per tenant or per plan. These are provider-API
//! facts that change only when a provider ships a model — a reviewed diff plus a
//! deploy is the right cadence, and a migration that must land in Neon before the
//! gateway that reads it (CLAUDE.md rule 5) would add a deploy-ordering hazard for
//! no gain. If the founder wants them live-editable, this module's three lookup
//! functions are the only seam to move.
//!
//! **Fail direction: CLOSED.** A table that does not parse (a broken edit — the
//! unit tests make that a red build, not a runtime surprise) validates no effort and
//! maps no level, so a request carrying `reasoning_effort` is refused rather than
//! sent with a guessed budget.

use std::sync::OnceLock;

use serde_json::Value;

/// What the Anthropic adapter must put on the wire for one effort level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnthropicThinking {
    /// Send no `thinking` field at all.
    Omit,
    /// `thinking: {"type": "disabled"}`.
    Disabled,
    /// `thinking: {"type": "between_tools"}` (Sonnet 5.5's off switch).
    BetweenTools,
    /// `thinking: {"type": "adaptive"}` plus `output_config.effort`.
    Adaptive { effort: String },
    /// `thinking: {"type": "enabled", "budget_tokens": N}`.
    Budget(u32),
}

/// What the Gemini / Vertex adapter must put in `generationConfig.thinkingConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GeminiThinking {
    /// `thinkingLevel` (Gemini 3.x), already in Google's upper-case spelling.
    Level(String),
    /// `thinkingBudget` in tokens (Gemini 2.5 and earlier).
    Budget(u32),
}

#[derive(Debug)]
struct Family<T> {
    model_contains: Vec<String>,
    /// effort word -> value; a missing key and an explicit `null` both mean
    /// "this provider cannot honour that level".
    levels: Vec<(String, Option<T>)>,
}

/// Caps on what a caller may send and on what the gateway relays back (spec §5).
/// `Default` is all zeros — the FAIL-CLOSED reading of a table that did not parse:
/// no `stop` accepted, no upstream message relayed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Limits {
    pub stop_max_entries: usize,
    pub stop_max_bytes: usize,
    pub user_max_bytes: usize,
    pub provider_message_max_chars: usize,
    /// `OG-10`: the ceiling, in seconds, on an upstream `Retry-After` the gateway will
    /// honour or relay. 0 (the unparseable-table default) means "ignore the header".
    pub retry_after_max_secs: u64,
}

/// `OG-07`: the Realtime session caps. Zeros are never produced — a table that does not
/// parse yields no policy at all ([`realtime_policy`] is `None`) and the route refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RealtimeLimits {
    pub max_session_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_client_message_bytes: usize,
    pub max_upstream_message_bytes: usize,
    pub connect_timeout_secs: u64,
    /// `M-4` (security re-review 2026-10-02): ALLOW verdicts on a session's scanned events
    /// are coalesced into ONE ledger row per this many seconds (plus one at session end),
    /// instead of one row per event.
    pub verdict_coalesce_window_secs: u64,
    /// `M-4`: the most non-allow, non-terminal verdicts (warn, fail-open, an observed
    /// redact) one session may record individually; past it the session closes 1008
    /// `verdict_limit`. A block always records — it ends the session.
    pub max_recorded_verdicts_per_session: u32,
    /// rev5 `M1`: how often (seconds) a live session re-checks the workspace controls, its
    /// key and its hard budgets — besides after every `response.done`.
    pub control_recheck_secs: u64,
    /// Deadline for each control check; timeout closes the session fail-closed.
    pub control_recheck_timeout_secs: u64,
}

/// `OG-07`: one realtime model's price card, USD per million tokens.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RealtimeCard {
    pub model: String,
    pub text_in: f64,
    pub audio_in: f64,
    pub cached_text_in: f64,
    /// `None` = no published cached-audio rate; callers charge the uncached audio rate.
    pub cached_audio_in: Option<f64>,
    pub text_out: f64,
    pub audio_out: f64,
}

/// `M4` (security review 2026-10-02): how many realtime sessions may be open at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RealtimeSessionCaps {
    pub max_per_tenant: usize,
    pub max_process: usize,
    /// `L-2` (security re-review 2026-10-02): the last this-many process slots only open a
    /// tenant's FIRST session, so tenants already holding sessions cannot exhaust the cap.
    pub process_reserved_for_new_tenants: usize,
}

/// `OG-07` (CLAUDE.md §23): everything the Realtime relay reads from this table.
#[derive(Debug)]
pub(crate) struct RealtimePolicy {
    pub providers: Vec<String>,
    pub model_contains: Vec<String>,
    pub limits: RealtimeLimits,
    pub sessions: RealtimeSessionCaps,
    pub cards: Vec<RealtimeCard>,
}

/// `OG-91`: how a mode-T upstream error is re-shaped for a Responses client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ErrorMapping {
    /// Lower-cased substrings of an upstream 400/413 message meaning "context overflow".
    pub context_overflow_message_contains: Vec<String>,
    /// Upstream statuses meaning "overloaded, retry".
    pub overloaded_statuses: Vec<u16>,
    pub overloaded_retry_after_default_secs: u64,
}

/// `M3` (security review 2026-10-02): the `GET /v1/models` per-tenant cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModelsListPolicy {
    pub cache_ttl_secs: u64,
    pub cache_max_tenants: usize,
}

/// `OG-08`: a native (non-catalog) provider the passthrough serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PassthroughNative {
    pub id: String,
    /// The header that carries the tenant's BYOK key upstream.
    pub auth_header: String,
    /// Sent when the caller did not supply the header (`anthropic-version`).
    pub default_headers: Vec<(String, String)>,
}

/// `OG-08` (CLAUDE.md §23): the passthrough's caps and its native provider list.
#[derive(Debug)]
pub(crate) struct PassthroughPolicy {
    pub max_request_body_bytes: u64,
    pub upstream_timeout_secs: u64,
    pub native: Vec<PassthroughNative>,
}

/// `C1` (security review 2026-10-02): the value shape an allowlisted unmodelled chat field
/// may carry. A shape mismatch is a 400 — a `string` where a number belongs is text no rail
/// was told to expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtraShape {
    Number,
    Bool,
    String,
    ObjectOfNumbers,
    ArrayOfStrings,
    /// An object whose values are bool / number / null only (no text, no nesting).
    ObjectOfNonTextScalars,
    /// Any JSON; every string leaf is scanned and captured.
    Json,
}

impl ExtraShape {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "number" => Self::Number,
            "bool" => Self::Bool,
            "string" => Self::String,
            "object_of_numbers" => Self::ObjectOfNumbers,
            "array_of_strings" => Self::ArrayOfStrings,
            "object_of_non_text_scalars" => Self::ObjectOfNonTextScalars,
            "json" => Self::Json,
            _ => return None,
        })
    }

    /// Does `v` have this shape?
    #[must_use]
    pub(crate) fn accepts(self, v: &Value) -> bool {
        match self {
            Self::Number => v.is_number(),
            Self::Bool => v.is_boolean(),
            Self::String => v.is_string(),
            Self::ObjectOfNumbers => v
                .as_object()
                .is_some_and(|o| o.values().all(Value::is_number)),
            Self::ArrayOfStrings => v.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
            Self::ObjectOfNonTextScalars => v.as_object().is_some_and(|o| {
                o.values()
                    .all(|x| x.is_boolean() || x.is_number() || x.is_null())
            }),
            Self::Json => true,
        }
    }

    /// The shape's name, for the 400 message.
    #[must_use]
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Number => "a number",
            Self::Bool => "a boolean",
            Self::String => "a string",
            Self::ObjectOfNumbers => "an object of numbers",
            Self::ArrayOfStrings => "an array of strings",
            Self::ObjectOfNonTextScalars => "an object of boolean / number values",
            Self::Json => "JSON",
        }
    }
}

#[derive(Debug)]
struct Table {
    /// `C1`: the unmodelled chat fields the gateway forwards, with their value shapes.
    extra_allow: Vec<(String, ExtraShape)>,
    realtime: RealtimePolicy,
    passthrough: PassthroughPolicy,
    limits: Limits,
    efforts: Vec<String>,
    anthropic_min_budget: u32,
    /// `OG-05`: lower-cased model names that only the Responses API serves.
    bridge_responses_only: Vec<String>,
    /// `OG-05`: models that serve chat completions but need Responses for tools.
    bridge_tools_need_responses: Vec<String>,
    anthropic: Vec<Family<AnthropicThinking>>,
    gemini: Vec<Family<GeminiThinking>>,
    /// `OG-02` D8: `(model substrings, placeholder)` for Gemini's thought-signature check.
    gemini_signature: Option<(Vec<String>, String)>,
    /// `D9`: lower-cased substrings naming a Cohere vision model.
    cohere_vision: Vec<String>,
    /// `OG-06`: caps for the media / files / batch routes.
    media: MediaLimits,
    /// `M3`: the `GET /v1/models` cache.
    models_list: ModelsListPolicy,
    /// `OG-91`: mode-T error re-shaping.
    error_mapping: ErrorMapping,
}

/// `OG-06` §5: caps and ceilings for the media, files and batch routes. `Default` is all
/// zeros — the FAIL-CLOSED reading of a table that did not parse: every upload is "too
/// large", no batch line count is allowed, so nothing is forwarded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MediaLimits {
    /// JSON-bodied media routes (images, speech, moderations, rerank).
    pub json_body_max_bytes: usize,
    /// `POST /v1/files` for every purpose but `batch` (streamed, never buffered).
    pub file_upload_max_bytes: usize,
    /// `purpose=batch` JSONL, buffered and validated line by line (spec §3.2).
    pub batch_jsonl_max_bytes: usize,
    pub batch_max_lines: usize,
    pub batch_line_max_bytes: usize,
    /// `images/edits` multipart.
    pub image_upload_max_bytes: usize,
    /// `audio/transcriptions` and `/translations` multipart.
    pub audio_upload_max_bytes: usize,
    /// The speech `input` text, in characters.
    pub speech_input_max_chars: usize,
    /// A non-file multipart field (`model`, `purpose`, `prompt`, …).
    pub multipart_text_field_max_bytes: usize,
    pub multipart_max_parts: usize,
    /// Bytes buffered while the routing fields (`model` / `purpose`) have not been seen
    /// because a file part came first. Past it the upload is refused 413.
    pub multipart_prescan_max_bytes: usize,
    /// A provider's reply to a buffered media call (images, transcripts, rerank).
    pub media_response_max_bytes: usize,
    pub media_timeout_secs: u64,
    pub files_timeout_secs: u64,
    /// Pagination `limit` ceiling forwarded on list routes.
    pub list_limit_max: u32,
    /// `H3`: process-wide MiB of buffered request bodies (0 = nothing may be buffered).
    pub body_buffer_budget_mb: usize,
    /// `H3`: one tenant's concurrent body reads (0 = none).
    pub uploads_per_tenant_max: usize,
    /// `H3`: `Retry-After` on a busy refusal.
    pub busy_retry_after_secs: u64,
    /// `M-3` (security re-review 2026-10-02): the MiB of buffered request bodies ONE tenant
    /// may hold at once (0 = none), so a few tenants cannot hold the whole process budget.
    pub body_buffer_tenant_share_mb: usize,
    /// `M-3`: the longest gap between two chunks of a request body being read (0 = refuse).
    pub body_read_idle_timeout_secs: u64,
    /// `M-3`: the longest a buffered request-body read may take in all (0 = refuse).
    pub body_read_total_timeout_secs: u64,
    /// `M-F` (security re-review 2026-10-03): the longest a STREAMED upload's body may take
    /// in all, from its first byte (the idle bound is `body_read_idle_timeout_secs`).
    pub body_stream_total_timeout_secs: u64,
    /// `M-F`: MiB of the process budget kept back — a reservation may take the free MiB
    /// below this only while its tenant holds at most `body_buffer_reserve_tenant_max_mb`.
    pub body_buffer_reserved_for_new_tenants_mb: usize,
    /// `M-F`: the most one tenant may hold while drawing on the reserve.
    pub body_buffer_reserve_tenant_max_mb: usize,
    /// Final re-review `M-4` (2026-10-03): a FREE tenant's share (no control plane counts as
    /// free) — free workspaces cost nothing to create, so theirs is the smaller one.
    pub body_buffer_free_tenant_share_mb: usize,
    /// `M-4`: what a free tenant may hold while drawing on the reserve (0 = never), so the
    /// reserve is always there for a paying tenant holding nothing.
    pub body_buffer_free_reserve_tenant_max_mb: usize,
    /// LAST review `MED-3` (2026-10-03): what ALL free tenants together may hold, so a paying
    /// tenant always finds room for a full body outside the reserve.
    pub body_buffer_free_tenants_total_mb: usize,
}

static TABLE: OnceLock<Option<Table>> = OnceLock::new();

fn table() -> Option<&'static Table> {
    TABLE
        .get_or_init(|| parse(include_str!("../../translation_policy.v1.json")))
        .as_ref()
}

fn parse_anthropic(v: &Value) -> Option<Option<AnthropicThinking>> {
    match v {
        Value::Null => Some(None),
        Value::String(s) => match s.as_str() {
            "omit" => Some(Some(AnthropicThinking::Omit)),
            "disabled" => Some(Some(AnthropicThinking::Disabled)),
            "between_tools" => Some(Some(AnthropicThinking::BetweenTools)),
            _ => None,
        },
        Value::Object(o) => {
            if let Some(e) = o.get("effort").and_then(Value::as_str) {
                Some(Some(AnthropicThinking::Adaptive {
                    effort: e.to_owned(),
                }))
            } else {
                let n = o.get("budget_tokens").and_then(Value::as_u64)?;
                Some(Some(AnthropicThinking::Budget(u32::try_from(n).ok()?)))
            }
        }
        _ => None,
    }
}

fn parse_gemini(v: &Value) -> Option<Option<GeminiThinking>> {
    match v {
        Value::Null => Some(None),
        Value::String(s) => Some(Some(GeminiThinking::Level(s.clone()))),
        Value::Number(n) => Some(Some(GeminiThinking::Budget(
            u32::try_from(n.as_u64()?).ok()?,
        ))),
        _ => None,
    }
}

fn parse_families<T>(v: &Value, leaf: fn(&Value) -> Option<Option<T>>) -> Option<Vec<Family<T>>> {
    let mut out = Vec::new();
    for f in v.get("families")?.as_array()? {
        let model_contains = f
            .get("model_contains")?
            .as_array()?
            .iter()
            .map(|m| m.as_str().map(str::to_ascii_lowercase))
            .collect::<Option<Vec<_>>>()?;
        let mut levels = Vec::new();
        for (k, lv) in f.get("levels")?.as_object()? {
            levels.push((k.clone(), leaf(lv)?));
        }
        out.push(Family {
            model_contains,
            levels,
        });
    }
    Some(out)
}

/// `Some(Some(..))` for a well-formed `thought_signature` block; `None` for a malformed one
/// (which fails the whole table closed, like every other malformed block).
fn parse_signature(v: &Value) -> Option<Option<(Vec<String>, String)>> {
    let models = v
        .get("model_contains")?
        .as_array()?
        .iter()
        .map(|m| m.as_str().map(str::to_ascii_lowercase))
        .collect::<Option<Vec<_>>>()?;
    let placeholder = v.get("placeholder")?.as_str()?.to_owned();
    if placeholder.is_empty() {
        return None;
    }
    Some(Some((models, placeholder)))
}

fn parse_realtime(v: &Value) -> Option<RealtimePolicy> {
    let strings = |k: &str| -> Option<Vec<String>> {
        v.get(k)?
            .as_array()?
            .iter()
            .map(|m| m.as_str().map(str::to_ascii_lowercase))
            .collect()
    };
    let l = v.get("limits")?;
    let n = |k: &str| -> Option<u64> { l.get(k)?.as_u64().filter(|x| *x > 0) };
    let limits = RealtimeLimits {
        max_session_secs: n("max_session_secs")?,
        idle_timeout_secs: n("idle_timeout_secs")?,
        max_client_message_bytes: usize::try_from(n("max_client_message_bytes")?).ok()?,
        max_upstream_message_bytes: usize::try_from(n("max_upstream_message_bytes")?).ok()?,
        connect_timeout_secs: n("connect_timeout_secs")?,
        verdict_coalesce_window_secs: n("verdict_coalesce_window_secs")?,
        max_recorded_verdicts_per_session: u32::try_from(n("max_recorded_verdicts_per_session")?)
            .ok()?,
        control_recheck_secs: n("control_recheck_secs")?,
        control_recheck_timeout_secs: n("control_recheck_timeout_secs")?,
    };
    let rate = |c: &Value, k: &str| -> Option<f64> {
        c.get(k)?.as_f64().filter(|x| x.is_finite() && *x >= 0.0)
    };
    let mut cards = Vec::new();
    for c in v.get("price_cards")?.as_array()? {
        let cached_audio_in = match c.get("cached_audio_in")? {
            Value::Null => None,
            other => Some(other.as_f64().filter(|x| x.is_finite() && *x >= 0.0)?),
        };
        cards.push(RealtimeCard {
            model: c.get("model")?.as_str()?.to_ascii_lowercase(),
            text_in: rate(c, "text_in")?,
            audio_in: rate(c, "audio_in")?,
            cached_text_in: rate(c, "cached_text_in")?,
            cached_audio_in,
            text_out: rate(c, "text_out")?,
            audio_out: rate(c, "audio_out")?,
        });
    }
    let providers = strings("providers")?;
    let model_contains = strings("model_contains")?;
    if providers.is_empty() || model_contains.is_empty() {
        return None;
    }
    let sv = v.get("sessions")?;
    let cap = |k: &str| -> Option<usize> {
        usize::try_from(sv.get(k)?.as_u64().filter(|x| *x > 0)?).ok()
    };
    let sessions = RealtimeSessionCaps {
        max_per_tenant: cap("max_per_tenant")?,
        max_process: cap("max_process")?,
        process_reserved_for_new_tenants: cap("process_reserved_for_new_tenants")?,
    };
    // A reserve that covers the whole cap would leave no slot for a tenant's second
    // session at all: refuse the table (fail-CLOSED — no policy, no realtime).
    if sessions.process_reserved_for_new_tenants >= sessions.max_process {
        return None;
    }
    // Longest model name first, so a card for `gpt-realtime-2.1` is matched before the
    // shorter `gpt-realtime` whatever order the JSON lists them in.
    cards.sort_by_key(|c| std::cmp::Reverse(c.model.len()));
    Some(RealtimePolicy {
        providers,
        model_contains,
        limits,
        sessions,
        cards,
    })
}

fn parse_passthrough(v: &Value) -> Option<PassthroughPolicy> {
    let mut native = Vec::new();
    for p in v.get("native_providers")?.as_array()? {
        let mut default_headers = Vec::new();
        for (k, val) in p.get("default_headers")?.as_object()? {
            default_headers.push((k.to_ascii_lowercase(), val.as_str()?.to_owned()));
        }
        native.push(PassthroughNative {
            id: p.get("id")?.as_str()?.to_owned(),
            auth_header: p.get("auth_header")?.as_str()?.to_ascii_lowercase(),
            default_headers,
        });
    }
    Some(PassthroughPolicy {
        max_request_body_bytes: v
            .get("max_request_body_bytes")?
            .as_u64()
            .filter(|x| *x > 0)?,
        upstream_timeout_secs: v
            .get("upstream_timeout_secs")?
            .as_u64()
            .filter(|x| *x > 0)?,
        native,
    })
}

fn parse_media(m: &Value) -> Option<MediaLimits> {
    let n = |k: &str| -> Option<usize> { usize::try_from(m.get(k)?.as_u64()?).ok() };
    Some(MediaLimits {
        json_body_max_bytes: n("json_body_max_bytes")?,
        file_upload_max_bytes: n("file_upload_max_bytes")?,
        batch_jsonl_max_bytes: n("batch_jsonl_max_bytes")?,
        batch_max_lines: n("batch_max_lines")?,
        batch_line_max_bytes: n("batch_line_max_bytes")?,
        image_upload_max_bytes: n("image_upload_max_bytes")?,
        audio_upload_max_bytes: n("audio_upload_max_bytes")?,
        speech_input_max_chars: n("speech_input_max_chars")?,
        multipart_text_field_max_bytes: n("multipart_text_field_max_bytes")?,
        multipart_max_parts: n("multipart_max_parts")?,
        multipart_prescan_max_bytes: n("multipart_prescan_max_bytes")?,
        media_response_max_bytes: n("media_response_max_bytes")?,
        media_timeout_secs: u64::try_from(n("media_timeout_secs")?).ok()?,
        files_timeout_secs: u64::try_from(n("files_timeout_secs")?).ok()?,
        list_limit_max: u32::try_from(n("list_limit_max")?).ok()?,
        body_buffer_budget_mb: n("body_buffer_budget_mb")?,
        uploads_per_tenant_max: n("uploads_per_tenant_max")?,
        busy_retry_after_secs: u64::try_from(n("busy_retry_after_secs")?).ok()?,
        body_buffer_tenant_share_mb: n("body_buffer_tenant_share_mb")?,
        body_read_idle_timeout_secs: u64::try_from(n("body_read_idle_timeout_secs")?).ok()?,
        body_read_total_timeout_secs: u64::try_from(n("body_read_total_timeout_secs")?).ok()?,
        body_stream_total_timeout_secs: u64::try_from(n("body_stream_total_timeout_secs")?).ok()?,
        body_buffer_reserved_for_new_tenants_mb: n("body_buffer_reserved_for_new_tenants_mb")?,
        body_buffer_reserve_tenant_max_mb: n("body_buffer_reserve_tenant_max_mb")?,
        body_buffer_free_tenant_share_mb: n("body_buffer_free_tenant_share_mb")?,
        body_buffer_free_reserve_tenant_max_mb: n("body_buffer_free_reserve_tenant_max_mb")?,
        body_buffer_free_tenants_total_mb: n("body_buffer_free_tenants_total_mb")?,
    })
    // M-F: a reserve that covers the whole budget, or a per-tenant allowance larger than the
    // reserve, is not a reserve — refuse the table (fail-CLOSED: all zeros, nothing buffered).
    .filter(|m| {
        m.body_buffer_reserved_for_new_tenants_mb < m.body_buffer_budget_mb
            && m.body_buffer_reserve_tenant_max_mb <= m.body_buffer_reserved_for_new_tenants_mb
            // M-4: the free reserve allowance is at most the paid one; the free share is at
            // most the paid share and still fits a full batch file.
            && m.body_buffer_free_reserve_tenant_max_mb <= m.body_buffer_reserve_tenant_max_mb
            && m.body_buffer_free_tenant_share_mb <= m.body_buffer_tenant_share_mb
            && m.body_buffer_free_tenant_share_mb.saturating_mul(1024 * 1024)
                >= m.batch_jsonl_max_bytes
            // MED-3: the free tenants' combined cap holds at least one free share, and leaves
            // the reserve plus a full batch body for a paying tenant.
            && m.body_buffer_free_tenants_total_mb >= m.body_buffer_free_tenant_share_mb
            && m.body_buffer_free_tenants_total_mb
                + m.body_buffer_reserved_for_new_tenants_mb
                + m.batch_jsonl_max_bytes.div_ceil(1024 * 1024)
                <= m.body_buffer_budget_mb
    })
}

fn parse(raw: &str) -> Option<Table> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let efforts = v
        .get("efforts")?
        .as_array()?
        .iter()
        .map(|e| e.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let a = v.get("anthropic")?;
    let anthropic_min_budget = u32::try_from(a.get("min_budget_tokens")?.as_u64()?).ok()?;
    let l = v.get("limits")?;
    let field = |k: &str| -> Option<usize> { usize::try_from(l.get(k)?.as_u64()?).ok() };
    let limits = Limits {
        stop_max_entries: field("stop_max_entries")?,
        stop_max_bytes: field("stop_max_bytes")?,
        user_max_bytes: field("user_max_bytes")?,
        provider_message_max_chars: field("provider_message_max_chars")?,
        retry_after_max_secs: u64::try_from(field("retry_after_max_secs")?).ok()?,
    };
    let names = |k: &str| -> Option<Vec<String>> {
        v.get("responses_bridge")?
            .get(k)?
            .as_array()?
            .iter()
            .map(|m| m.as_str().map(str::to_ascii_lowercase))
            .collect()
    };
    let mut extra_allow = Vec::new();
    for (k, shape) in v.get("extra_params")?.get("allow")?.as_object()? {
        extra_allow.push((k.clone(), ExtraShape::parse(shape.as_str()?)?));
    }
    Some(Table {
        extra_allow,
        realtime: parse_realtime(v.get("realtime")?)?,
        passthrough: parse_passthrough(v.get("passthrough")?)?,
        limits,
        efforts,
        anthropic_min_budget,
        bridge_responses_only: names("responses_only_models")?,
        bridge_tools_need_responses: names("tools_need_responses")?,
        anthropic: parse_families(a, parse_anthropic)?,
        gemini: parse_families(v.get("gemini")?, parse_gemini)?,
        gemini_signature: parse_signature(v.get("gemini")?.get("thought_signature")?)?,
        cohere_vision: v
            .get("cohere")?
            .get("vision_model_contains")?
            .as_array()?
            .iter()
            .map(|m| m.as_str().map(str::to_ascii_lowercase))
            .collect::<Option<Vec<_>>>()?,
        media: parse_media(v.get("media")?)?,
        error_mapping: {
            let e = v.get("error_mapping")?;
            ErrorMapping {
                context_overflow_message_contains: e
                    .get("context_overflow_message_contains")?
                    .as_array()?
                    .iter()
                    .map(|m| m.as_str().map(str::to_ascii_lowercase))
                    .collect::<Option<Vec<_>>>()?,
                overloaded_statuses: e
                    .get("overloaded_statuses")?
                    .as_array()?
                    .iter()
                    .map(|s| s.as_u64().and_then(|n| u16::try_from(n).ok()))
                    .collect::<Option<Vec<_>>>()?,
                overloaded_retry_after_default_secs: e
                    .get("overloaded_retry_after_default_secs")?
                    .as_u64()?,
            }
        },
        models_list: ModelsListPolicy {
            cache_ttl_secs: v.pointer("/models_list/cache_ttl_secs")?.as_u64()?,
            cache_max_tenants: usize::try_from(
                v.pointer("/models_list/cache_max_tenants")?.as_u64()?,
            )
            .ok()?,
        },
    })
}

fn lookup<'a, T>(families: &'a [Family<T>], model: &str, effort: &str) -> Option<&'a T> {
    let model = model.to_ascii_lowercase();
    // First family whose substring list matches; an EMPTY list is the catch-all.
    let fam = families.iter().find(|f| {
        f.model_contains.is_empty() || f.model_contains.iter().any(|m| model.contains(m.as_str()))
    })?;
    fam.levels
        .iter()
        .find(|(k, _)| k == effort)
        .and_then(|(_, v)| v.as_ref())
}

/// Does `model` name `name` exactly, or a DATED snapshot of it (`name-2026-10-01`,
/// `name-20261001`)? A sibling (`gpt-5.5-pro` vs `gpt-5.5`) never matches, and neither does
/// a VERSION suffix (`gpt-realtime-2` is not a snapshot of `gpt-realtime`): only a date is.
fn names_model(model: &str, name: &str) -> bool {
    fn is_date(r: &str) -> bool {
        let b = r.as_bytes();
        let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
        (b.len() == 10
            && b[4] == b'-'
            && b[7] == b'-'
            && digits(&b[..4])
            && digits(&b[5..7])
            && digits(&b[8..]))
            || (b.len() == 8 && digits(b))
    }
    model == name
        || model
            .strip_prefix(name)
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(is_date)
}

/// `OG-05` §3.4: must an OpenAI chat request for `model` go through the
/// Responses API? True for a Responses-only model, and for a "tools need
/// Responses" model when the request carries tools. **Fails to `false` on an
/// unparseable table** — the request then goes the chat route and the provider's
/// own 4xx answers, which is honest; nothing is silently rewritten.
pub(crate) fn responses_bridge_applies(model: &str, has_tools: bool) -> bool {
    let Some(t) = table() else {
        return false;
    };
    let m = model.to_ascii_lowercase();
    let m = m.strip_prefix("openai/").unwrap_or(&m);
    t.bridge_responses_only.iter().any(|n| names_model(m, n))
        || (has_tools
            && t.bridge_tools_need_responses
                .iter()
                .any(|n| names_model(m, n)))
}

/// `C1`: the shape an unmodelled chat field may carry, or `None` when the field is not
/// forwarded at all. **Fails CLOSED**: an unparseable table allowlists nothing, so every
/// unmodelled field is refused.
pub(crate) fn extra_param_shape(key: &str) -> Option<ExtraShape> {
    table()?
        .extra_allow
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, s)| *s)
}

/// `B-594`: the cold-lookup throttle (`auth_throttle` block; `preauth_limiter.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthThrottlePolicy {
    /// Tokens a source starts with (≥ 1).
    pub burst: u32,
    /// Tokens regained per minute (≥ 1).
    pub refill_per_minute: u32,
    /// Buckets held at once (≥ 1); past it, sources share one overflow bucket.
    pub max_sources: usize,
    /// The IPv6 network one source is, 32..=64.
    pub ipv6_prefix_len: u8,
    /// The WIDER IPv6 network that must ALSO have a token, 16..=`ipv6_prefix_len`
    /// (equal = no second bucket). One /48 holds 65,536 /64s; without it one site buys
    /// 65,536 buckets (security review rev4 H1).
    pub ipv6_wide_prefix_len: u8,
    /// Least time between sweeps of refilled buckets when the map is full (≥ 1).
    pub sweep_interval_ms: u64,
    /// Concurrent store-reaching key lookups, as a percent of the Postgres pool's
    /// `max_size` (1..=100; at least one slot) — the GLOBAL bound per-source buckets
    /// cannot give (H1).
    pub cold_lookup_pool_pct: u8,
    /// How long a cold lookup may wait for a slot before it is refused 429 (0 = never waits).
    pub cold_lookup_wait_ms: u64,
    /// TCP peers whose forwarding headers are believed (L2).
    pub trusted_proxy_cidrs: Vec<Cidr>,
    /// The header a trusted peer names the client in, lower-case ("" = none: then the
    /// rightmost `x-forwarded-for` entry, then the peer).
    pub client_ip_header: String,
    /// Least time between two refreshes of the valid-key set that a MISS triggers (≥ 1).
    pub known_keys_refresh_ms: u64,
    /// Longest a miss waits for that refresh before falling back to the gated lookup (≥ 1).
    pub known_keys_wait_ms: u64,
    /// A set older than this is reloaded whole (dropping revoked keys) instead of
    /// reading only new rows (≥ 1).
    pub known_keys_full_reload_secs: u64,
    /// How far behind the last refresh a delta read starts — covers a row that
    /// commits after a later-stamped one (≥ 1).
    pub known_keys_overlap_secs: u64,
    /// Past this many valid keys the set is not used (the gated lookup is).
    pub known_keys_max: usize,
}

/// One CIDR block (`10.0.0.0/8`, `fc00::/7`). IPv4 is held IPv4-mapped, so one
/// 128-bit compare serves both families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    net: u128,
    mask: u128,
}

impl Cidr {
    /// `a.b.c.d/n` or `x::y/n`. `None` for anything else — a prefix wider than the
    /// family, or host bits set (a typo, not a network).
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let (addr, len) = s.trim().split_once('/')?;
        let ip: std::net::IpAddr = addr.parse().ok()?;
        let len: u32 = len.parse().ok()?;
        let (bits, len) = match ip {
            std::net::IpAddr::V4(a) if len <= 32 => (u128::from(a.to_ipv6_mapped()), 96 + len),
            std::net::IpAddr::V6(a) if len <= 128 => (u128::from(a), len),
            _ => return None,
        };
        let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
        (bits & !mask == 0).then_some(Self { net: bits, mask })
    }

    /// Whether `ip` (IPv4-mapped IPv6 counts as IPv4) is inside the block.
    pub(crate) fn contains(&self, ip: std::net::IpAddr) -> bool {
        let bits = match ip.to_canonical() {
            std::net::IpAddr::V4(a) => u128::from(a.to_ipv6_mapped()),
            std::net::IpAddr::V6(a) => u128::from(a),
        };
        bits & self.mask == self.net
    }
}

/// Used ONLY when the shipped `auth_throttle` block does not parse — which a unit
/// test (`b594_the_shipped_auth_throttle_block_parses`) makes unreachable in a tested
/// build, and the same test holds this equal to the shipped JSON. Neither open nor
/// closed: the limiter keeps running at the documented values, because a typo must
/// neither disable it nor refuse everyone.
fn auth_throttle_fallback() -> AuthThrottlePolicy {
    AuthThrottlePolicy {
        burst: 60,
        refill_per_minute: 60,
        max_sources: 100_000,
        ipv6_prefix_len: 64,
        ipv6_wide_prefix_len: 48,
        sweep_interval_ms: 1_000,
        cold_lookup_pool_pct: 25,
        cold_lookup_wait_ms: 500,
        trusted_proxy_cidrs: [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "::1/128",
            "fc00::/7",
        ]
        .iter()
        .filter_map(|c| Cidr::parse(c))
        .collect(),
        client_ip_header: "cf-connecting-ip".to_owned(),
        known_keys_refresh_ms: 1_000,
        known_keys_wait_ms: 2_000,
        known_keys_full_reload_secs: 3_600,
        known_keys_overlap_secs: 300,
        known_keys_max: 1_000_000,
    }
}

fn parse_auth_throttle(v: &Value) -> Option<AuthThrottlePolicy> {
    let n = |k: &str| v.get(k).and_then(Value::as_u64);
    let pos = |k: &str| n(k).filter(|x| *x >= 1);
    let ipv6_prefix_len = u8::try_from(n("ipv6_prefix_len")?)
        .ok()
        .filter(|l| (32..=64).contains(l))?;
    let mut trusted_proxy_cidrs = Vec::new();
    for c in v.get("trusted_proxy_cidrs")?.as_array()? {
        trusted_proxy_cidrs.push(Cidr::parse(c.as_str()?)?);
    }
    let client_ip_header = v
        .get("client_ip_header")?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    if !client_ip_header.is_empty()
        && axum::http::HeaderName::from_bytes(client_ip_header.as_bytes()).is_err()
    {
        return None;
    }
    Some(AuthThrottlePolicy {
        burst: u32::try_from(pos("burst")?).ok()?,
        refill_per_minute: u32::try_from(pos("refill_per_minute")?).ok()?,
        max_sources: usize::try_from(pos("max_sources")?).ok()?,
        ipv6_prefix_len,
        ipv6_wide_prefix_len: u8::try_from(n("ipv6_wide_prefix_len")?)
            .ok()
            .filter(|l| (16..=ipv6_prefix_len).contains(l))?,
        sweep_interval_ms: pos("sweep_interval_ms")?,
        cold_lookup_pool_pct: u8::try_from(n("cold_lookup_pool_pct")?)
            .ok()
            .filter(|p| (1..=100).contains(p))?,
        cold_lookup_wait_ms: n("cold_lookup_wait_ms")?,
        trusted_proxy_cidrs,
        client_ip_header,
        known_keys_refresh_ms: pos("known_keys_refresh_ms")?,
        known_keys_wait_ms: pos("known_keys_wait_ms")?,
        known_keys_full_reload_secs: pos("known_keys_full_reload_secs")?,
        known_keys_overlap_secs: pos("known_keys_overlap_secs")?,
        known_keys_max: usize::try_from(pos("known_keys_max")?).ok()?,
    })
}

fn parse_auth_throttle_table(raw: &str) -> Option<AuthThrottlePolicy> {
    let v: Value = serde_json::from_str(raw).ok()?;
    parse_auth_throttle(v.get("auth_throttle")?)
}

/// `B-594`: the cold-lookup throttle policy, parsed once and on its own — a bad
/// `auth_throttle` block cannot void the translation table, nor the reverse.
pub(crate) fn auth_throttle_policy() -> &'static AuthThrottlePolicy {
    static P: OnceLock<AuthThrottlePolicy> = OnceLock::new();
    P.get_or_init(|| {
        parse_auth_throttle_table(include_str!("../../translation_policy.v1.json"))
            .unwrap_or_else(|| {
                tracing::warn!(
                    "translation_policy.v1.json auth_throttle block did not parse — using the documented defaults"
                );
                auth_throttle_fallback()
            })
    })
}

/// `OG-20` / `OG-23`: the write-side bounds (`key_policy` block). The policy-document
/// half is handed to `tracelane_shared::key_policy::KeyPolicy::parse`; the two project
/// counts are the project routes' own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyPolicyLimits {
    pub document: tracelane_shared::key_policy::WriteLimits,
    pub max_projects_per_tenant: usize,
    pub max_environments_per_project: usize,
}

/// Used ONLY when the shipped `key_policy` block does not parse — which
/// `og20_the_shipped_key_policy_block_parses` makes unreachable in a tested build. The
/// documented values: a typo must neither lift the bounds nor refuse every write.
const KEY_POLICY_FALLBACK: KeyPolicyLimits = KeyPolicyLimits {
    document: tracelane_shared::key_policy::WriteLimits {
        max_patterns: 64,
        max_pattern_chars: 128,
        max_cidrs: 64,
        max_required_keys: 32,
        max_per_model_limits: 32,
        max_alert_thresholds: 10,
    },
    max_projects_per_tenant: 100,
    max_environments_per_project: 16,
};

fn parse_key_policy_table(raw: &str) -> Option<KeyPolicyLimits> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let v = v.get("key_policy")?;
    let n = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n >= 1)
    };
    Some(KeyPolicyLimits {
        document: tracelane_shared::key_policy::WriteLimits {
            max_patterns: n("max_patterns")?,
            max_pattern_chars: n("max_pattern_chars")?,
            max_cidrs: n("max_cidrs")?,
            max_required_keys: n("max_required_keys")?,
            max_per_model_limits: n("max_per_model_limits")?,
            max_alert_thresholds: n("max_alert_thresholds")?,
        },
        max_projects_per_tenant: n("max_projects_per_tenant")?,
        max_environments_per_project: n("max_environments_per_project")?,
    })
}

/// `OG-20` / `OG-23`: the policy and project write bounds, parsed once and on their own.
pub(crate) fn key_policy_limits() -> KeyPolicyLimits {
    static P: OnceLock<KeyPolicyLimits> = OnceLock::new();
    *P.get_or_init(|| {
        parse_key_policy_table(include_str!("../../translation_policy.v1.json")).unwrap_or_else(
            || {
                tracing::warn!(
                    "translation_policy.v1.json key_policy block did not parse — using the documented defaults"
                );
                KEY_POLICY_FALLBACK
            },
        )
    })
}

/// `OG-07`: the Realtime policy, or `None` if the table did not parse (the route then
/// refuses 503 — fail-CLOSED; a relay with no caps is not served).
pub(crate) fn realtime_policy() -> Option<&'static RealtimePolicy> {
    table().map(|t| &t.realtime)
}

/// `OG-07`: the price card for a realtime model — the exact name or a DATED snapshot of
/// it (`gpt-realtime-2.1-2026-10-01`), never a sibling (`gpt-realtime-2.1-mini`).
pub(crate) fn realtime_card(model: &str) -> Option<&'static RealtimeCard> {
    let m = model.to_ascii_lowercase();
    let m = m.strip_prefix("openai/").unwrap_or(&m);
    realtime_policy()?
        .cards
        .iter()
        .find(|c| names_model(m, &c.model))
}

/// `OG-08`: the passthrough policy, or `None` if the table did not parse (fail-CLOSED).
pub(crate) fn passthrough_policy() -> Option<&'static PassthroughPolicy> {
    table().map(|t| &t.passthrough)
}

/// The request-translation limits; all zeros (fail-closed) if the table did not parse.
pub(crate) fn limits() -> Limits {
    table().map_or_else(Limits::default, |t| t.limits)
}

/// `OG-91`: the mode-T error mapping; empty (nothing re-shaped — the pre-OG-91 answers) if
/// the table did not parse.
pub(crate) fn error_mapping() -> ErrorMapping {
    table().map_or_else(ErrorMapping::default, |t| t.error_mapping.clone())
}

/// `M3`: the `GET /v1/models` cache policy. An unparseable table yields a zero TTL (every
/// call reads the store — correct, only slower) and a zero cap.
pub(crate) fn models_list_policy() -> ModelsListPolicy {
    table().map_or(
        ModelsListPolicy {
            cache_ttl_secs: 0,
            cache_max_tenants: 0,
        },
        |t| t.models_list,
    )
}

/// `OG-06`: the media / files / batch caps; all zeros (fail-closed) if the table did not parse.
pub(crate) fn media_limits() -> MediaLimits {
    table().map_or_else(MediaLimits::default, |t| t.media)
}

/// `D9`: does this Cohere model take images? `false` on an unparseable table (refuse).
pub(crate) fn cohere_is_vision_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    table().is_some_and(|t| t.cohere_vision.iter().any(|m| model.contains(m.as_str())))
}

/// True when `effort` is one of the table's efforts. An unparseable table has none.
pub(crate) fn is_valid_effort(effort: &str) -> bool {
    table().is_some_and(|t| t.efforts.iter().any(|e| e == effort))
}

/// The efforts the table accepts, for the 400 message.
pub(crate) fn valid_efforts() -> Vec<&'static str> {
    table().map_or_else(Vec::new, |t| t.efforts.iter().map(String::as_str).collect())
}

/// Anthropic's smallest legal `budget_tokens`.
pub(crate) fn anthropic_min_budget() -> Option<u32> {
    table().map(|t| t.anthropic_min_budget)
}

/// The Anthropic thinking control for `(model, effort)`. `None` = cannot be honoured.
pub(crate) fn anthropic_thinking(model: &str, effort: &str) -> Option<&'static AnthropicThinking> {
    lookup(&table()?.anthropic, model, effort)
}

/// `OG-02` D8: the thought-signature placeholder to put on the first `functionCall` of a
/// replayed assistant turn for `model`, or `None` when the model does not validate one (or
/// the table did not parse — then no signature is invented).
pub(crate) fn gemini_signature_placeholder(model: &str) -> Option<&'static str> {
    let (models, placeholder) = table()?.gemini_signature.as_ref()?;
    let model = model.to_ascii_lowercase();
    models
        .iter()
        .any(|m| model.contains(m.as_str()))
        .then_some(placeholder.as_str())
}

/// The Gemini thinking control for `(model, effort)`. `None` = cannot be honoured.
pub(crate) fn gemini_thinking(model: &str, effort: &str) -> Option<&'static GeminiThinking> {
    lookup(&table()?.gemini, model, effort)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn og20_the_shipped_key_policy_block_parses() {
        let p = parse_key_policy_table(include_str!("../../translation_policy.v1.json"))
            .expect("key_policy block must parse");
        assert_eq!(p, key_policy_limits());
        // A zero or a missing bound is refused, never read as "unbounded".
        for bad in [
            r#"{"key_policy":{"max_patterns":0,"max_pattern_chars":1,"max_cidrs":1,"max_required_keys":1,"max_projects_per_tenant":1,"max_environments_per_project":1}}"#,
            r#"{"key_policy":{"max_patterns":1,"max_pattern_chars":1,"max_cidrs":1,"max_required_keys":1,"max_projects_per_tenant":1}}"#,
        ] {
            assert!(parse_key_policy_table(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn b594_the_shipped_auth_throttle_block_parses() {
        // The fallback is reachable only through a block that does not parse; this
        // makes that unreachable in a tested build.
        let p = parse_auth_throttle_table(include_str!("../../translation_policy.v1.json"))
            .expect("auth_throttle block must parse");
        assert_eq!(&p, auth_throttle_policy());
        assert_eq!(
            p,
            auth_throttle_fallback(),
            "the fallback must equal the shipped table"
        );
        assert!((32..=64).contains(&p.ipv6_prefix_len));
        // A bad value is refused, not clamped into something nobody wrote. Each case
        // breaks exactly ONE field of an otherwise valid block.
        let good: Value =
            serde_json::from_str(include_str!("../../translation_policy.v1.json")).expect("json");
        let good = good["auth_throttle"].clone();
        for (field, bad) in [
            ("burst", serde_json::json!(0)),
            ("ipv6_prefix_len", serde_json::json!(128)),
            ("sweep_interval_ms", Value::Null),
            ("ipv6_wide_prefix_len", serde_json::json!(80)),
            ("cold_lookup_pool_pct", serde_json::json!(0)),
            ("cold_lookup_pool_pct", serde_json::json!(101)),
            ("trusted_proxy_cidrs", serde_json::json!(["10.0.0.1/8"])),
            ("trusted_proxy_cidrs", serde_json::json!(["10.0.0.0/33"])),
            ("client_ip_header", serde_json::json!("bad header")),
            ("known_keys_refresh_ms", serde_json::json!(0)),
            ("known_keys_max", Value::Null),
        ] {
            let mut b = good.clone();
            b[field] = bad.clone();
            let raw = serde_json::json!({ "auth_throttle": b }).to_string();
            assert!(
                parse_auth_throttle_table(&raw).is_none(),
                "{field} = {bad} must be refused"
            );
        }
    }

    #[test]
    fn b594_cidrs_match_their_network_and_nothing_else() {
        let c = |s: &str| Cidr::parse(s).unwrap_or_else(|| panic!("{s}"));
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(c("172.16.0.0/12").contains(ip("172.31.255.1")));
        assert!(!c("172.16.0.0/12").contains(ip("172.32.0.1")));
        assert!(
            c("10.0.0.0/8").contains(ip("::ffff:10.1.2.3")),
            "mapped = v4"
        );
        assert!(c("fc00::/7").contains(ip("fd12::1")));
        assert!(!c("fc00::/7").contains(ip("2001:db8::1")));
        assert!(c("::1/128").contains(ip("::1")));
        assert!(!c("::1/128").contains(ip("::2")));
        assert!(c("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(
            !c("0.0.0.0/0").contains(ip("2001:db8::1")),
            "v4 /0 is v4 only"
        );
        for bad in ["10.0.0.0", "10.0.0.0/33", "10.0.0.1/8", "zz/8", "::/129"] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_embedded_table_parses_and_every_family_covers_every_effort() {
        let t = table().expect("translation_policy.v1.json must parse");
        assert!(!t.efforts.is_empty());
        for e in &t.efforts {
            for fam in &t.anthropic {
                assert!(
                    fam.levels.iter().any(|(k, _)| k == e),
                    "anthropic family {:?} lacks level {e}",
                    fam.model_contains
                );
            }
            for fam in &t.gemini {
                assert!(
                    fam.levels.iter().any(|(k, _)| k == e),
                    "gemini family {:?} lacks level {e}",
                    fam.model_contains
                );
            }
        }
        // A catch-all family exists for each provider so an unknown model resolves.
        assert!(t.anthropic.iter().any(|f| f.model_contains.is_empty()));
        assert!(t.gemini.iter().any(|f| f.model_contains.is_empty()));
    }

    #[test]
    fn every_budget_in_the_table_is_legal_for_anthropic() {
        let t = table().expect("table");
        for fam in &t.anthropic {
            for (k, v) in &fam.levels {
                if let Some(AnthropicThinking::Budget(n)) = v {
                    assert!(
                        *n >= t.anthropic_min_budget,
                        "{k}: budget {n} is below Anthropic's minimum"
                    );
                }
            }
        }
    }

    #[test]
    fn the_limits_match_spec_section_5() {
        assert_eq!(
            limits(),
            Limits {
                stop_max_entries: 4,
                stop_max_bytes: 256,
                user_max_bytes: 256,
                provider_message_max_chars: 512,
                retry_after_max_secs: 3600,
            }
        );
    }

    #[test]
    fn the_thought_signature_placeholder_applies_to_gemini_3_only() {
        assert_eq!(
            gemini_signature_placeholder("gemini-3-pro"),
            Some("skip_thought_signature_validator")
        );
        assert_eq!(
            gemini_signature_placeholder("google/Gemini-3.1-flash"),
            Some("skip_thought_signature_validator")
        );
        assert_eq!(gemini_signature_placeholder("gemini-2.5-pro"), None);
        assert_eq!(gemini_signature_placeholder("claude-opus-5-5"), None);
    }

    #[test]
    fn the_effort_vocabulary_includes_max() {
        for e in ["none", "minimal", "low", "medium", "high", "xhigh", "max"] {
            assert!(is_valid_effort(e), "{e}");
        }
        assert!(!is_valid_effort("ultra"));
        assert!(!is_valid_effort(""));
        assert!(!is_valid_effort("HIGH"));
    }

    #[test]
    fn anthropic_families_resolve_by_model_in_table_order() {
        // Extended-only models get a budget, never adaptive.
        assert_eq!(
            anthropic_thinking("claude-haiku-4-5-20251001", "medium"),
            Some(&AnthropicThinking::Budget(8192))
        );
        // Opus 5.5 is matched BEFORE the catch-all, and cannot turn thinking off.
        assert_eq!(anthropic_thinking("claude-opus-5-5", "none"), None);
        assert_eq!(
            anthropic_thinking("claude-opus-5-5", "xhigh"),
            Some(&AnthropicThinking::Adaptive {
                effort: "xhigh".into()
            })
        );
        // Sonnet 5.5's off switch is between_tools, not disabled.
        assert_eq!(
            anthropic_thinking("claude-sonnet-5-5", "none"),
            Some(&AnthropicThinking::BetweenTools)
        );
        // 4.6 has no xhigh: it maps up to max rather than sending a level it rejects.
        assert_eq!(
            anthropic_thinking("claude-sonnet-4-6", "xhigh"),
            Some(&AnthropicThinking::Adaptive {
                effort: "max".into()
            })
        );
        // Anything newer falls to the adaptive default.
        assert_eq!(
            anthropic_thinking("claude-opus-9", "none"),
            Some(&AnthropicThinking::Disabled)
        );
        // An unknown EFFORT is never mapped.
        assert_eq!(anthropic_thinking("claude-opus-9", "ultra"), None);
    }

    #[test]
    fn gemini_three_uses_a_level_and_older_models_a_budget() {
        assert_eq!(
            gemini_thinking("gemini-3.1-pro", "high"),
            Some(&GeminiThinking::Level("HIGH".into()))
        );
        assert_eq!(
            gemini_thinking("vertex/gemini-3-flash", "max"),
            Some(&GeminiThinking::Level("HIGH".into()))
        );
        assert_eq!(
            gemini_thinking("gemini-3.1-pro", "none"),
            Some(&GeminiThinking::Level("MINIMAL".into()))
        );
        assert_eq!(
            gemini_thinking("gemini-2.5-flash", "none"),
            Some(&GeminiThinking::Budget(0))
        );
        assert_eq!(
            gemini_thinking("gemini-2.5-pro", "medium"),
            Some(&GeminiThinking::Budget(8192))
        );
    }

    #[test]
    fn og05_the_bridge_list_matches_names_and_dated_snapshots_never_siblings() {
        // Responses-only: bridged with or without tools.
        for m in [
            "gpt-5.5-pro",
            "gpt-5.3-codex",
            "openai/gpt-5.5-pro",
            "GPT-5.5-PRO",
        ] {
            assert!(responses_bridge_applies(m, false), "{m}");
            assert!(responses_bridge_applies(m, true), "{m}");
        }
        assert!(responses_bridge_applies("gpt-5.5-pro-2026-10-01", false));
        // Tools-need-Responses: bridged ONLY when tools are present.
        // F1 (live 2026-10-03): gpt-6-sol / gpt-6-luna take chat tools only at
        // reasoning_effort none — a live 400 without the bridge — so they bridge with tools.
        for m in ["gpt-6-astra", "gpt-6.1-sol", "gpt-6-sol", "gpt-6-luna"] {
            assert!(responses_bridge_applies(m, true), "{m}");
            assert!(!responses_bridge_applies(m, false), "{m} serves plain chat");
        }
        // Siblings and ordinary models are never bridged.
        for m in [
            "gpt-5.5",
            "gpt-6-sol-mini",
            "gpt-6-astra-mini",
            "gpt-4o",
            "claude-opus-5-5",
        ] {
            assert!(
                !responses_bridge_applies(m, true),
                "{m} must not be bridged"
            );
        }
    }

    #[test]
    fn og07_the_realtime_policy_parses_with_the_spec_defaults() {
        let p = realtime_policy().expect("realtime block parses");
        assert_eq!(p.providers, vec!["openai".to_owned()]);
        assert_eq!(p.limits.max_session_secs, 30 * 60, "spec §3.3: 30 min");
        assert_eq!(p.limits.idle_timeout_secs, 2 * 60, "spec §3.3: 2 min");
        assert!(p.limits.max_client_message_bytes > 0);
    }

    #[test]
    fn og07_a_realtime_card_matches_the_name_and_dated_snapshots_never_a_sibling() {
        let c = realtime_card("gpt-realtime-2.1").expect("card");
        assert_eq!(
            (c.text_in, c.audio_in, c.text_out, c.audio_out),
            (4.0, 32.0, 24.0, 64.0)
        );
        assert!(realtime_card("openai/gpt-realtime-2.1").is_some());
        assert!(realtime_card("gpt-realtime-2.1-2026-10-01").is_some());
        assert!(realtime_card("gpt-realtime-2.1-mini").is_none());
        assert!(realtime_card("gpt-realtime-2").is_none());
        assert!(realtime_card("gpt-5").is_none());
    }

    /// Security review 2026-10-02: the new reference-table blocks parse, and a dated snapshot
    /// is the only suffix a card covers — `gpt-realtime-2` is NOT a snapshot of the
    /// `gpt-realtime` card (it would be priced at another model's rates).
    #[test]
    fn secfix_the_new_blocks_parse_and_only_a_date_suffix_is_a_snapshot() {
        assert_eq!(
            extra_param_shape("logit_bias"),
            Some(ExtraShape::ObjectOfNumbers)
        );
        assert_eq!(
            extra_param_shape("chat_template_kwargs"),
            Some(ExtraShape::ObjectOfNonTextScalars)
        );
        for refused in [
            "prompt",
            "functions",
            "function_call",
            "prediction",
            "documents",
        ] {
            assert_eq!(extra_param_shape(refused), None, "{refused}");
        }
        let m = media_limits();
        assert!(m.body_buffer_budget_mb * 1024 * 1024 > m.batch_jsonl_max_bytes);
        assert!(m.uploads_per_tenant_max > 0 && m.busy_retry_after_secs > 0);
        let s = realtime_policy().expect("policy").sessions;
        assert_eq!(s.max_per_tenant, 10, "decision M4: default 10");
        // L-2: a reserve for first sessions, strictly inside the process cap.
        assert!(
            s.process_reserved_for_new_tenants > 0
                && s.process_reserved_for_new_tenants < s.max_process
        );
        // M-3: one tenant's share fits the largest buffered cap and is less than the whole
        // budget; both read timeouts are set.
        assert!(m.body_buffer_tenant_share_mb * 1024 * 1024 >= m.batch_jsonl_max_bytes);
        assert!(m.body_buffer_tenant_share_mb < m.body_buffer_budget_mb);
        // M-4: free tenants get a smaller share that still fits a full batch file, and never
        // draw on the reserve.
        assert!(m.body_buffer_free_tenant_share_mb < m.body_buffer_tenant_share_mb);
        assert!(m.body_buffer_free_tenant_share_mb * 1024 * 1024 >= m.batch_jsonl_max_bytes);
        assert_eq!(m.body_buffer_free_reserve_tenant_max_mb, 0);
        assert!(m.body_read_idle_timeout_secs > 0);
        assert!(m.body_read_total_timeout_secs >= m.body_read_idle_timeout_secs);
        // M-F: the streamed-upload total is set, at least the buffered total and at most the
        // files timeout that already ends the upstream request; the reserve is a real reserve
        // and its per-tenant allowance fits a JSON body.
        assert!(m.body_stream_total_timeout_secs >= m.body_read_total_timeout_secs);
        assert!(m.body_stream_total_timeout_secs <= m.files_timeout_secs);
        assert!(
            m.body_buffer_reserved_for_new_tenants_mb > 0
                && m.body_buffer_reserved_for_new_tenants_mb < m.body_buffer_budget_mb
        );
        assert!(
            m.body_buffer_reserve_tenant_max_mb > 0
                && m.body_buffer_reserve_tenant_max_mb <= m.body_buffer_reserved_for_new_tenants_mb
                && m.body_buffer_reserve_tenant_max_mb * 1024 * 1024 >= m.json_body_max_bytes
        );
        // M-4: the verdict coalescing window and the per-session record cap are set.
        let rl = realtime_policy().expect("policy").limits;
        assert!(rl.verdict_coalesce_window_secs > 0 && rl.max_recorded_verdicts_per_session > 0);
        assert!(models_list_policy().cache_ttl_secs > 0);
        let em = error_mapping();
        assert!(em.overloaded_statuses.contains(&529));
        assert!(
            em.context_overflow_message_contains
                .iter()
                .any(|p| p == "prompt is too long")
        );
        assert!(realtime_card("gpt-realtime").is_some());
        assert!(realtime_card("gpt-realtime-2025-08-28").is_some());
        assert_eq!(
            realtime_card("gpt-realtime-2.1").map(|c| c.model.as_str()),
            Some("gpt-realtime-2.1"),
            "the longer card wins"
        );
        assert!(realtime_card("gpt-realtime-2").is_none());
        assert!(realtime_card("gpt-4o-realtime-preview-2024-12-17").is_some());
    }

    #[test]
    fn realtime_requires_a_positive_control_deadline() {
        let table: Value =
            serde_json::from_str(include_str!("../../translation_policy.v1.json")).expect("table");
        let mut realtime = table["realtime"].clone();
        assert!(parse_realtime(&realtime).is_some());
        realtime["limits"]["control_recheck_timeout_secs"] = serde_json::json!(0);
        assert!(parse_realtime(&realtime).is_none());
        realtime["limits"]
            .as_object_mut()
            .expect("limits")
            .remove("control_recheck_timeout_secs");
        assert!(parse_realtime(&realtime).is_none());
    }

    #[test]
    fn og08_the_passthrough_policy_parses_and_names_only_header_authable_natives() {
        let p = passthrough_policy().expect("passthrough block parses");
        assert!(p.max_request_body_bytes > 0);
        assert_eq!(p.upstream_timeout_secs, 300, "spec §5");
        let ids: Vec<&str> = p.native.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["anthropic", "google"]);
        for refused in ["bedrock", "vertex", "azure"] {
            assert!(
                !ids.contains(&refused),
                "{refused} cannot be reached by a static header"
            );
        }
    }
}
