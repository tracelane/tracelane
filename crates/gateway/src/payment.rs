//! x402 / AP2 / ACP payment event processor.
//!
//! Extracts payment span attributes from gateway requests and records them
//! day one."
//!
//! Span vocabulary:
//!   - payment.intent  — agent declared intent to pay
//!   - payment.mandate — signed AP2 Mandate verified
//!   - payment.settled — x402 settlement event captured
//!
//! Callers: `chat_completions_handler` in server.rs — fire-and-forget via
//! `tokio::spawn` after auth so the hot path is not blocked by Postgres writes.

use anyhow::{Context as _, Result};
use tracelane_shared::TenantId;
use uuid::Uuid;

/// Payment event types mirroring the x402 / AP2 span vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentEventType {
    Intent,
    Mandate,
    Settled,
}

impl PaymentEventType {
    /// Returns the Postgres CHECK constraint–compatible string value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Mandate => "mandate",
            Self::Settled => "settled",
        }
    }
}

/// Parsed x402 payment event from span attributes.
#[derive(Debug, Clone)]
pub struct PaymentEvent {
    pub tenant_id: TenantId,
    pub agent_id: Option<String>,
    pub trace_id: Uuid,
    pub span_id: Uuid,
    pub event_type: PaymentEventType,
    pub amount_usd: Option<f64>,
    pub recipient: Option<String>,
    pub mandate_id: Option<String>,
}

/// Extract a payment event from the request body if `tracelane_payment` is present.
///
/// Returns `None` if the request has no payment metadata — the common case.
/// The `tracelane_payment` key is never forwarded to the upstream provider;
/// it is stripped from the proxied body by the provider adapters.
///
/// Parameters:
/// - `body`     — raw parsed request JSON
/// - `tenant_id` — from JWT claim (never from body)
/// - `agent_id`  — from `x-agent-id` header
/// - `trace_id`  — from `x-trace-id` header or generated
pub fn extract_payment_event(
    body: &serde_json::Value,
    tenant_id: &TenantId,
    agent_id: Option<&str>,
    trace_id: Uuid,
) -> Option<PaymentEvent> {
    let meta = body.get("tracelane_payment")?;
    let event_type = match meta.get("type")?.as_str()? {
        "intent" => PaymentEventType::Intent,
        "mandate" => PaymentEventType::Mandate,
        "settled" => PaymentEventType::Settled,
        other => {
            tracing::warn!(event_type = other, "unknown payment event type — ignoring");
            return None;
        }
    };
    Some(PaymentEvent {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.map(str::to_owned),
        trace_id,
        span_id: Uuid::new_v4(),
        event_type,
        amount_usd: meta.get("amount_usd").and_then(|v| v.as_f64()),
        recipient: meta
            .get("recipient")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        mandate_id: meta
            .get("mandate_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    })
}

/// Persist a payment event to the Postgres `payment_events` table.
///
/// Fire-and-forget — caller should `tokio::spawn` this.
/// Errors are logged by the caller; this function returns the full error
/// for the spawn wrapper to log with context.
///
/// Parameters:
/// - `pool` — Postgres deadpool connection pool
/// - `ev`   — fully-populated `PaymentEvent`
#[tracing::instrument(skip(pool, ev), fields(
    tenant_id = %ev.tenant_id,
    event_type = ev.event_type.as_str(),
))]
pub async fn record_payment_event(pool: &deadpool_postgres::Pool, ev: PaymentEvent) -> Result<()> {
    let client = pool.get().await.context("payment_events: pool acquire")?;
    client
        .execute(
            "INSERT INTO payment_events \
             (tenant_id, agent_id, trace_id, span_id, event_type, amount_usd, recipient, mandate_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                ev.tenant_id.as_uuid(),
                &ev.agent_id,
                &ev.trace_id,
                &ev.span_id,
                &ev.event_type.as_str(),
                &ev.amount_usd,
                &ev.recipient,
                &ev.mandate_id,
            ],
        )
        .await
        .context("payment_events: INSERT failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn tid() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    #[test]
    fn extract_returns_none_when_no_payment_key() {
        let body = json!({ "model": "claude-sonnet-4-6", "messages": [] });
        assert!(extract_payment_event(&body, &tid(), None, Uuid::new_v4()).is_none());
    }

    #[test]
    fn extract_intent_event() {
        let body = json!({
            "model": "claude-sonnet-4-6",
            "tracelane_payment": {
                "type": "intent",
                "amount_usd": 0.05,
                "recipient": "addr_abc"
            }
        });
        let ev = extract_payment_event(&body, &tid(), Some("agent-42"), Uuid::new_v4())
            .expect("should extract");
        assert_eq!(ev.event_type, PaymentEventType::Intent);
        assert_eq!(ev.amount_usd, Some(0.05));
        assert_eq!(ev.recipient.as_deref(), Some("addr_abc"));
        assert_eq!(ev.agent_id.as_deref(), Some("agent-42"));
    }

    #[test]
    fn extract_mandate_event() {
        let body = json!({
            "tracelane_payment": {
                "type": "mandate",
                "mandate_id": "mnd_xyz"
            }
        });
        let ev =
            extract_payment_event(&body, &tid(), None, Uuid::new_v4()).expect("should extract");
        assert_eq!(ev.event_type, PaymentEventType::Mandate);
        assert_eq!(ev.mandate_id.as_deref(), Some("mnd_xyz"));
    }

    #[test]
    fn extract_settled_event() {
        let body = json!({
            "tracelane_payment": { "type": "settled", "amount_usd": 1.0 }
        });
        let ev =
            extract_payment_event(&body, &tid(), None, Uuid::new_v4()).expect("should extract");
        assert_eq!(ev.event_type, PaymentEventType::Settled);
    }

    #[test]
    fn extract_unknown_type_returns_none() {
        let body = json!({ "tracelane_payment": { "type": "refund" } });
        assert!(extract_payment_event(&body, &tid(), None, Uuid::new_v4()).is_none());
    }
}
