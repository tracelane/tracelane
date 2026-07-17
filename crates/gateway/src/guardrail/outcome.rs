//! Guardrail outcome vocabulary — the shared types the dispatcher and every
//! rail speak (the guardrail spec §2.5, §5).
//!
//! A rail returns `Result<RailOutcome, RailError>`. The dispatcher stamps
//! per-rail latency, maps a `RailError` to the rail's fail-mode, aggregates
//! the per-rail [`Outcome`]s into a single [`Decision`] using the precedence
//! `block > redact > warn > allow`, and records the lot to the ledger.
//!
//! Callers: `guardrail::dispatcher` (aggregation), every `guardrail::rails::*`
//! rail (returns `RailOutcome`), `guardrail::recorder` (serializes the
//! verdict). Invariant: `details` carry no raw secret/PII/full-prompt text
//! (§2.5) — rails construct bounded, redacted detail objects.

use serde::Serialize;

/// Which side of the request/response flow a rail evaluates (§2.5 `side`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    /// Request-side: everything between `accept()` and the upstream call.
    Request,
    /// Response-side: upstream response → client, including SSE streaming.
    Response,
}

impl Side {
    /// Stable lowercase id for the ClickHouse column / metric label (§2.5).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Request => "request",
            Side::Response => "response",
        }
    }
}

/// The set of sides a rail participates in. Many rails (R2, R4, R7) run on
/// both; cost caps (R1) run request-side + streaming, format (R5) response-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sides {
    RequestOnly,
    ResponseOnly,
    Both,
}

impl Sides {
    /// Does this rail run on `side`?
    #[must_use]
    pub fn includes(self, side: Side) -> bool {
        matches!(
            (self, side),
            (Sides::Both, _)
                | (Sides::RequestOnly, Side::Request)
                | (Sides::ResponseOnly, Side::Response)
        )
    }
}

/// Fail-mode policy for a rail (§0). The dispatcher consults this when a rail
/// returns [`RailError`] (error / timeout / unavailability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// Security rails (R2-secret, R3, R4, R8): on error → **block** (fail
    /// closed). A detected-but-unverifiable threat must never pass.
    Closed,
    /// Quality rails (R5, R6, R7): on error → **proceed**, but a `fail_open`
    /// verdict MUST be recorded with the reason. A silent skip is a P0 defect.
    OpenLoud,
}

/// The per-rail outcome label recorded in the ledger (§2.5 `rails[].outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Rail ran and found nothing actionable.
    Allow,
    /// Security/policy violation → short-circuit the upstream call (4xx).
    Block,
    /// Sensitive content rewritten in place (R2 secret/PII, R6 leak, R7
    /// competitor). The payload is mutated; the request proceeds.
    Redact,
    /// Soft signal — request proceeds, recorded for observability/alerting.
    Warn,
    /// The signal this rail needs is absent (e.g. no tool calls for R3). NOT a
    /// failure — distinct from `fail_open` (§2.1 population rules).
    NotApplicable,
    /// A quality rail hit an error/timeout and failed **open** (proceeded).
    /// Always carries a reason; the loudness lives in this recorded verdict.
    FailOpen,
}

impl Outcome {
    /// Aggregation severity, `block > redact > warn > allow` (§2.6). `Allow`,
    /// `NotApplicable`, and `FailOpen` all mean "the request proceeds" → 0;
    /// they are distinguished in the recorded verdict, not in the decision.
    #[must_use]
    pub fn severity(self) -> u8 {
        match self {
            Outcome::Block => 3,
            Outcome::Redact => 2,
            Outcome::Warn => 1,
            Outcome::Allow | Outcome::NotApplicable | Outcome::FailOpen => 0,
        }
    }

    /// Stable snake_case label for metrics + the ledger (matches the serde
    /// repr exactly, §2.5/§4).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Block => "block",
            Outcome::Redact => "redact",
            Outcome::Warn => "warn",
            Outcome::NotApplicable => "not_applicable",
            Outcome::FailOpen => "fail_open",
        }
    }
}

/// The aggregate decision for one side, recorded once per side (§2.5
/// `decision`). Computed from the most severe per-rail [`Outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Block,
    Redact,
    Warn,
}

impl Decision {
    /// Fold the most-severe outcome into an aggregate decision (§2.6
    /// precedence). The default (nothing actionable) is `Allow`.
    #[must_use]
    pub fn from_outcomes<'a>(outcomes: impl IntoIterator<Item = &'a Outcome>) -> Self {
        let mut worst = Outcome::Allow;
        for o in outcomes {
            if o.severity() > worst.severity() {
                worst = *o;
            }
        }
        match worst {
            Outcome::Block => Decision::Block,
            Outcome::Redact => Decision::Redact,
            Outcome::Warn => Decision::Warn,
            Outcome::Allow | Outcome::NotApplicable | Outcome::FailOpen => Decision::Allow,
        }
    }

    /// Does this aggregate decision stop the upstream call?
    #[must_use]
    pub fn is_block(self) -> bool {
        matches!(self, Decision::Block)
    }

    /// Stable lowercase id for the ClickHouse column / metric label (§2.5).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Block => "block",
            Decision::Redact => "redact",
            Decision::Warn => "warn",
        }
    }
}

/// What a rail returns to the dispatcher. Latency, rail name, policy_version,
/// and model_version are stamped by the dispatcher (`recorder::RailRecord`);
/// the rail owns only the evaluation result.
#[derive(Debug, Clone, Serialize)]
pub struct RailOutcome {
    pub outcome: Outcome,
    /// ML/heuristic score in `[0,1]`. `None` for purely deterministic rails
    /// (R1–R7); set for R8 (§2.5 `score` is null for deterministic rails).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Decision threshold the score was compared against. `None` for
    /// deterministic rails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    /// Stable machine-readable reason (e.g. `TRIFECTA_EXFIL_IN_TAINTED_SESSION`).
    /// `None` only for a plain `allow` / `not_applicable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<&'static str>,
    /// Bounded, redacted, rail-specific context. MUST NOT contain raw secrets,
    /// full PII values, or full prompt text — redacted placeholders + offsets
    /// only (§2.5). Defaults to `null`.
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
}

impl RailOutcome {
    /// Rail ran, nothing actionable.
    #[must_use]
    pub fn allow() -> Self {
        Self::bare(Outcome::Allow, None)
    }

    /// The signal this rail needs is absent (§2.1). Not a failure.
    #[must_use]
    pub fn not_applicable() -> Self {
        Self::bare(Outcome::NotApplicable, None)
    }

    /// Block with a stable reason code.
    #[must_use]
    pub fn block(reason_code: &'static str) -> Self {
        Self::bare(Outcome::Block, Some(reason_code))
    }

    /// Redact (payload mutated) with a stable reason code.
    #[must_use]
    pub fn redact(reason_code: &'static str) -> Self {
        Self::bare(Outcome::Redact, Some(reason_code))
    }

    /// Warn with a stable reason code.
    #[must_use]
    pub fn warn(reason_code: &'static str) -> Self {
        Self::bare(Outcome::Warn, Some(reason_code))
    }

    /// A quality rail failed **open** (proceeded) after an error/timeout.
    /// Always carries the reason — the dispatcher constructs this when a
    /// `FailMode::OpenLoud` rail returns a [`RailError`] (§0 fail-open-loud; a
    /// silent skip is a P0 defect).
    #[must_use]
    pub fn fail_open(reason_code: &'static str) -> Self {
        Self::bare(Outcome::FailOpen, Some(reason_code))
    }

    fn bare(outcome: Outcome, reason_code: Option<&'static str>) -> Self {
        Self {
            outcome,
            score: None,
            threshold: None,
            reason_code,
            details: serde_json::Value::Null,
        }
    }

    /// Attach bounded, **already-redacted** rail-specific detail. Callers are
    /// responsible for not placing secrets/PII/full-prompt text here (§2.5;
    /// CI grep in the recorder is defense in depth, not the first line).
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Attach a heuristic score + threshold (R8).
    #[must_use]
    pub fn with_score(mut self, score: f64, threshold: f64) -> Self {
        self.score = Some(score);
        self.threshold = Some(threshold);
        self
    }
}

/// Error taxonomy for a rail evaluation (§5). The dispatcher maps every
/// variant to the rail's [`FailMode`] and records the reason — no `RailError`
/// is ever silently dropped.
#[derive(Debug, thiserror::Error)]
pub enum RailError {
    /// Required configuration is missing (treated per fail-mode).
    #[error("rail configuration missing: {0}")]
    ConfigMissing(&'static str),
    /// The rail exceeded its per-rail timeout. For a deterministic rail this
    /// means a bug (they finish in microseconds).
    #[error("rail evaluation timed out")]
    Timeout,
    /// A detector panicked; caught at the dispatcher seam via `catch_unwind`.
    #[error("rail detector panicked")]
    DetectorPanic,
    /// A dependency (e.g. the pinned-hash store) was unavailable.
    #[error("rail dependency unavailable: {0}")]
    DependencyUnavailable(&'static str),
}

impl RailError {
    /// The stable reason code recorded when this error maps to a fail-mode
    /// outcome (§2.5 `reason_code`).
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            RailError::ConfigMissing(_) => reason_codes::CONFIG_MISSING,
            RailError::Timeout => reason_codes::RAIL_TIMEOUT,
            RailError::DetectorPanic => reason_codes::DETECTOR_ERROR,
            RailError::DependencyUnavailable(_) => reason_codes::DEPENDENCY_UNAVAILABLE,
        }
    }
}

/// Stable, machine-readable reason codes (§3 per-rail `reason_codes`, plus the
/// cross-cutting fail-mode reasons from §5). Constants — never stringly typed
/// at a call site, so a rename is a single edit and the honesty-gate copy
/// scan can enumerate them.
pub mod reason_codes {
    // ── Cross-cutting (dispatcher / §5 RailError) ──────────────────────────
    pub const CONFIG_MISSING: &str = "CONFIG_MISSING";
    pub const RAIL_TIMEOUT: &str = "RAIL_TIMEOUT";
    /// A detector errored/panicked on a security rail → fail-closed block.
    pub const DETECTOR_ERROR: &str = "DETECTOR_ERROR";
    pub const DEPENDENCY_UNAVAILABLE: &str = "DEPENDENCY_UNAVAILABLE";

    // ── R1 cost / token / loop ─────────────────────────────────────────────
    pub const INPUT_TOKEN_CAP: &str = "INPUT_TOKEN_CAP";
    pub const OUTPUT_TOKEN_CAP: &str = "OUTPUT_TOKEN_CAP";
    pub const BUDGET_CAP: &str = "BUDGET_CAP";
    pub const LOOP_CAP: &str = "LOOP_CAP";
    /// Hard budget cap configured but session spend state is unknown (cache
    /// miss) → fail closed (§3 R1).
    pub const BUDGET_STATE_UNKNOWN: &str = "BUDGET_STATE_UNKNOWN";

    // ── R2 secrets + structured-PII ────────────────────────────────────────
    pub const SECRET_DETECTED: &str = "SECRET_DETECTED";
    pub const PII_CARD: &str = "PII_CARD";
    pub const PII_SSN: &str = "PII_SSN";
    pub const PII_EMAIL: &str = "PII_EMAIL";
    pub const PII_IBAN: &str = "PII_IBAN";
    pub const PII_PHONE: &str = "PII_PHONE";

    // ── R3 tool/MCP safety ─────────────────────────────────────────────────
    pub const TOOL_SCHEMA_INVALID: &str = "TOOL_SCHEMA_INVALID";
    pub const TOOL_ARG_POLICY: &str = "TOOL_ARG_POLICY";
    pub const TOOL_DEF_DRIFT: &str = "TOOL_DEF_DRIFT";
    pub const TOOL_DESC_INJECTION: &str = "TOOL_DESC_INJECTION";

    // ── R4 lethal trifecta ─────────────────────────────────────────────────
    pub const TRIFECTA_EXFIL_IN_TAINTED_SESSION: &str = "TRIFECTA_EXFIL_IN_TAINTED_SESSION";
    pub const TRIFECTA_UNKNOWN_TOOL_CAPS: &str = "TRIFECTA_UNKNOWN_TOOL_CAPS";

    // ── R5 output format ───────────────────────────────────────────────────
    pub const FORMAT_INVALID_JSON: &str = "FORMAT_INVALID_JSON";
    pub const FORMAT_SCHEMA_FAIL: &str = "FORMAT_SCHEMA_FAIL";
    pub const FORMAT_REGEX_FAIL: &str = "FORMAT_REGEX_FAIL";
    pub const FORMAT_REASK_EXHAUSTED: &str = "FORMAT_REASK_EXHAUSTED";

    // ── R6 system-prompt leak ──────────────────────────────────────────────
    pub const SYS_PROMPT_LEAK: &str = "SYS_PROMPT_LEAK";

    // ── R7 topic / competitor ──────────────────────────────────────────────
    pub const TOPIC_DENIED: &str = "TOPIC_DENIED";
    pub const COMPETITOR_MENTION: &str = "COMPETITOR_MENTION";

    // ── R8 prompt injection (heuristic) ────────────────────────────────────
    pub const INJECTION_DIRECT: &str = "INJECTION_DIRECT";
    pub const INJECTION_INDIRECT_RAG: &str = "INJECTION_INDIRECT_RAG";
    pub const INJECTION_INDIRECT_TOOL_RESULT: &str = "INJECTION_INDIRECT_TOOL_RESULT";
    pub const INJECTION_PROMPT_EXTRACTION: &str = "INJECTION_PROMPT_EXTRACTION";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sides_membership() {
        assert!(Sides::Both.includes(Side::Request));
        assert!(Sides::Both.includes(Side::Response));
        assert!(Sides::RequestOnly.includes(Side::Request));
        assert!(!Sides::RequestOnly.includes(Side::Response));
        assert!(Sides::ResponseOnly.includes(Side::Response));
        assert!(!Sides::ResponseOnly.includes(Side::Request));
    }

    #[test]
    fn severity_ordering_block_redact_warn_allow() {
        assert!(Outcome::Block.severity() > Outcome::Redact.severity());
        assert!(Outcome::Redact.severity() > Outcome::Warn.severity());
        assert!(Outcome::Warn.severity() > Outcome::Allow.severity());
        // not_applicable / fail_open never raise severity — request proceeds.
        assert_eq!(Outcome::NotApplicable.severity(), 0);
        assert_eq!(Outcome::FailOpen.severity(), 0);
    }

    #[test]
    fn aggregate_decision_takes_most_severe() {
        let mixed = [
            Outcome::Allow,
            Outcome::Warn,
            Outcome::Redact,
            Outcome::NotApplicable,
            Outcome::FailOpen,
        ];
        assert_eq!(Decision::from_outcomes(&mixed), Decision::Redact);

        let with_block = [Outcome::Redact, Outcome::Block, Outcome::Warn];
        assert_eq!(Decision::from_outcomes(&with_block), Decision::Block);
        assert!(Decision::from_outcomes(&with_block).is_block());

        // fail_open + not_applicable alone never block.
        let quality_failed = [Outcome::FailOpen, Outcome::NotApplicable, Outcome::Allow];
        assert_eq!(Decision::from_outcomes(&quality_failed), Decision::Allow);
        assert!(!Decision::from_outcomes(&quality_failed).is_block());
    }

    #[test]
    fn outcome_serializes_snake_case() {
        // §2.5 wire contract: not_applicable / fail_open are snake_case.
        assert_eq!(
            serde_json::to_string(&Outcome::NotApplicable).unwrap(),
            "\"not_applicable\""
        );
        assert_eq!(
            serde_json::to_string(&Outcome::FailOpen).unwrap(),
            "\"fail_open\""
        );
        assert_eq!(serde_json::to_string(&Outcome::Block).unwrap(), "\"block\"");
    }

    #[test]
    fn decision_and_side_serialize_lowercase() {
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&Side::Request).unwrap(),
            "\"request\""
        );
        assert_eq!(
            serde_json::to_string(&Side::Response).unwrap(),
            "\"response\""
        );
    }

    #[test]
    fn rail_outcome_omits_null_and_none_fields() {
        // A bare allow serializes compactly — no score/threshold/reason/details.
        let v = serde_json::to_value(RailOutcome::allow()).unwrap();
        assert_eq!(v, serde_json::json!({ "outcome": "allow" }));

        // A block with details keeps reason_code + details, still no score.
        let v = serde_json::to_value(
            RailOutcome::block(reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION)
                .with_details(serde_json::json!({ "legs": 3 })),
        )
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "outcome": "block",
                "reason_code": "TRIFECTA_EXFIL_IN_TAINTED_SESSION",
                "details": { "legs": 3 }
            })
        );
    }

    #[test]
    fn rail_outcome_score_roundtrip() {
        let v = serde_json::to_value(
            RailOutcome::warn(reason_codes::INJECTION_DIRECT).with_score(0.82, 0.5),
        )
        .unwrap();
        assert_eq!(v["score"], serde_json::json!(0.82));
        assert_eq!(v["threshold"], serde_json::json!(0.5));
        assert_eq!(v["outcome"], serde_json::json!("warn"));
    }

    #[test]
    fn rail_error_reason_codes_are_stable() {
        assert_eq!(
            RailError::DetectorPanic.reason_code(),
            reason_codes::DETECTOR_ERROR
        );
        assert_eq!(RailError::Timeout.reason_code(), reason_codes::RAIL_TIMEOUT);
        assert_eq!(
            RailError::DependencyUnavailable("pin-store").reason_code(),
            reason_codes::DEPENDENCY_UNAVAILABLE
        );
        assert_eq!(
            RailError::ConfigMissing("budget").reason_code(),
            reason_codes::CONFIG_MISSING
        );
    }
}
