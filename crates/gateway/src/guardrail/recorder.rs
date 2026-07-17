//! Verdict recorder (the guardrail spec §2.5, P0.4). Writes each
//! [`GuardrailVerdict`] to two places:
//!
//! 1. The **universal tamper-evident hash-chain** (`crate::audit::AuditChain`)
//!    via an `AuditEvent` — ungated, so the free tier gets a verifiable record.
//!    The Ed25519 signing path stays `f_audit_addon`-gated and is **not touched
//!    here** (the run-doc fence): appending a verdict event reuses the existing
//!    append API and never reaches the signing code.
//! 2. A **queryable ClickHouse mirror** (`tracelane.guardrail_verdicts`),
//!    best-effort / fire-and-forget like the audit log — a ClickHouse outage
//!    never blocks the request.
//!
//! Redaction (§2.5) runs before either write: `verdict.redact_in_place()`
//! scrubs credential byte-patterns from rail details.

use std::sync::Arc;

use crate::audit::{AuditChain, AuditEvent};
use crate::guardrail::context::GuardrailContext;
use crate::guardrail::dispatcher::SideOutcome;
use crate::guardrail::verdict::{GuardrailVerdict, VERDICT_SCHEMA};

/// Records guardrail verdicts to the ledger + ClickHouse.
pub struct GuardrailRecorder {
    audit_chain: Arc<AuditChain>,
    /// `None` when ClickHouse is unconfigured (dev) — the ledger record still
    /// lands; only the queryable mirror is skipped.
    ch: Option<clickhouse::Client>,
}

/// ClickHouse row for `tracelane.guardrail_verdicts`. `event_time` is micros
/// since epoch mapped to `DateTime64(6)` (mirrors `AuditLogRow`).
#[derive(Debug, Clone, serde::Serialize, clickhouse::Row)]
struct GuardrailVerdictRow {
    tenant_id: String,
    correlation_id: String,
    side: String,
    event_time: i64,
    decision: String,
    rails: String,
    total_latency_micros: u64,
    fail_open_rails: Vec<String>,
    schema_version: String,
}

impl GuardrailVerdictRow {
    /// Project a redacted verdict into the ClickHouse row shape.
    fn from_verdict(verdict: &GuardrailVerdict, event_time_micros: i64) -> Self {
        Self {
            tenant_id: verdict.tenant_id.clone(),
            correlation_id: verdict.correlation_id.clone(),
            side: verdict.side.as_str().to_string(),
            event_time: event_time_micros,
            decision: verdict.decision.as_str().to_string(),
            rails: verdict.rails_json(),
            total_latency_micros: verdict.total_latency_micros,
            fail_open_rails: verdict
                .fail_open_rails
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            schema_version: VERDICT_SCHEMA.to_string(),
        }
    }
}

impl GuardrailRecorder {
    #[must_use]
    pub fn new(audit_chain: Arc<AuditChain>, ch: Option<clickhouse::Client>) -> Self {
        Self { audit_chain, ch }
    }

    /// Record a side's verdict: build → redact → append to the ledger → mirror
    /// to ClickHouse. Errors are logged and swallowed (availability fail-open,
    /// matching the audit-log pattern) — recording must never block the request.
    pub async fn record(
        &self,
        side_outcome: &SideOutcome,
        ctx: &GuardrailContext<'_>,
        actor: &str,
    ) {
        if let Err(err) = self.record_to_ledger(side_outcome, ctx, actor).await {
            tracing::warn!(
                error = %err,
                side = side_outcome.side.as_str(),
                "guardrail verdict ledger append failed — request proceeds"
            );
        }
    }

    /// Build → redact → (spawn ClickHouse mirror) → append to the tamper-evident
    /// ledger; returns the **ledger-append** result. The `GuardrailEngine`
    /// surfaces this so the request path (and the e2e) can confirm the verdict
    /// was recorded even when the ClickHouse sink is absent — the exact prod
    /// degradation mode (`ch = None` → fail-open-loud: the ledger still gets the
    /// record). The ClickHouse mirror is best-effort and never affects this.
    pub(crate) async fn record_to_ledger(
        &self,
        side_outcome: &SideOutcome,
        ctx: &GuardrailContext<'_>,
        actor: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now();
        let ts_nanos = now.timestamp_nanos_opt().unwrap_or(0);
        let mut verdict = GuardrailVerdict::build(side_outcome, ctx, ts_nanos);
        // §2.5: scrub before anything is hashed or stored.
        verdict.redact_in_place();

        // (2) Queryable ClickHouse mirror — spawn first so a slow append can't
        // delay it; failure is logged, never propagated.
        if let Some(ch) = &self.ch {
            let row = GuardrailVerdictRow::from_verdict(&verdict, now.timestamp_micros());
            let ch = ch.clone();
            tokio::spawn(async move {
                if let Err(err) = write_verdict_row(&ch, row).await {
                    tracing::warn!(error = %err, "guardrail verdict ClickHouse write failed");
                }
            });
        }

        // (1) Universal hash-chain (ungated; Ed25519 signing path untouched).
        let payload = serde_json::to_value(&verdict)?;
        let event = AuditEvent {
            tenant_id: ctx.tenant_id.clone(),
            event_type: "guardrail.verdict",
            actor: actor.to_string(),
            payload,
        };
        self.audit_chain.append(event).await
    }
}

/// Insert one verdict row. Table is fully qualified so it resolves regardless
/// of the client's default database. Parameter binding via the `clickhouse::Row`
/// derive — no raw SQL strings (CLAUDE.md).
async fn write_verdict_row(
    ch: &clickhouse::Client,
    row: GuardrailVerdictRow,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut insert = ch
        .insert("tracelane.guardrail_verdicts")
        .context("clickhouse guardrail_verdicts insert init")?;
    insert
        .write(&row)
        .await
        .context("clickhouse guardrail_verdicts insert write")?;
    insert
        .end()
        .await
        .context("clickhouse guardrail_verdicts insert end")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::SessionState;
    use crate::guardrail::dispatcher::RailRecord;
    use crate::guardrail::outcome::{Decision, RailOutcome, Side, reason_codes};
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
    use ulid::Ulid;
    use uuid::Uuid;

    fn minimal_request() -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-6".to_string(),
            system: None,
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hi".to_string()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
        }
    }

    fn side_outcome() -> SideOutcome {
        SideOutcome {
            side: Side::Request,
            decision: Decision::Block,
            records: vec![RailRecord {
                rail: "R4_trifecta",
                policy_version: "r4@1",
                latency_micros: 12,
                outcome: RailOutcome::block(reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION),
            }],
            total_latency_micros: 99,
        }
    }

    #[test]
    fn row_projection_maps_every_column() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(0xBEEF));
        let req = minimal_request();
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        let verdict = GuardrailVerdict::build(&side_outcome(), &ctx, 1_700_000_000_000_000_000);
        let row = GuardrailVerdictRow::from_verdict(&verdict, 1_700_000_000_000_000);
        assert_eq!(row.tenant_id, Uuid::from_u128(0xBEEF).to_string());
        assert_eq!(row.side, "request");
        assert_eq!(row.decision, "block");
        assert_eq!(row.event_time, 1_700_000_000_000_000);
        assert_eq!(row.total_latency_micros, 99);
        assert_eq!(row.schema_version, VERDICT_SCHEMA);
        // rails column is a valid JSON array carrying the rail.
        let parsed: serde_json::Value = serde_json::from_str(&row.rails).unwrap();
        assert_eq!(parsed[0]["rail"], "R4_trifecta");
    }

    /// P0.4 done-test (ledger half): a verdict is appended to the real
    /// hash-chain (pool-less, no Ed25519) and the append succeeds. The
    /// ClickHouse half (a row appears) is a gated integration test — it needs a
    /// live ClickHouse and runs at the server wire-in step.
    #[tokio::test]
    async fn record_appends_verdict_to_ledger() {
        // Real AuditChain, no PG pool, no ClickHouse, no signing key.
        let chain = Arc::new(AuditChain::new(100, None, None).expect("audit chain"));
        let recorder = GuardrailRecorder::new(chain, None);

        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(0x1111));
        let req = minimal_request();
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            Some("apikey:test"),
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );

        // record_to_ledger returns the append result — it must be Ok (the
        // verdict event was hash-chained) even with ch = None.
        recorder
            .record_to_ledger(&side_outcome(), &ctx, "apikey:test")
            .await
            .expect("guardrail verdict must append to the ledger");

        // The public path also completes without panicking.
        recorder.record(&side_outcome(), &ctx, "apikey:test").await;
    }
}
