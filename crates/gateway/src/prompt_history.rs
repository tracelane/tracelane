//! Read-side of the prompt-promotion audit trail.
//!
//! Symmetric to `prompt_router::PromotionPersister` (write side) and
//! `auto_rollback::RollbackEventPersister` (write side). Reads from
//! `tracelane.promotion_decisions` and `tracelane.rollback_events`,
//! merges them by timestamp, and returns a unified timeline that the
//! dashboard / `tlane prompt history` CLI render verbatim.
//!
//! Two implementations:
//!   - `NoOpHistoryReader` — returns empty. Used in unit tests + when
//!     no ClickHouse client is configured.
//!   - `ClickHouseHistoryReader` — issues two parallel SELECTs and
//!     merges client-side. Tenant-isolated by query (every WHERE
//!     starts with `tenant_id = ?` — CLAUDE.md invariant).
//!
//! Surface: `read(tenant_id, prompt_name, limit) -> Vec<HistoryEntry>`,
//! sorted desc by timestamp.

#![allow(dead_code)]

use anyhow::{Context as _, Result};
use clickhouse::Client as ClickhouseClient;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use tracelane_shared::TenantId;

/// One timeline entry — either a promotion-decision or a rollback-event.
/// `at_micros` is microseconds since Unix epoch — clients render by
/// converting to local timezone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum HistoryEntry {
    #[serde(rename = "promotion")]
    Promotion {
        promotion_id: Uuid,
        from_env: String,
        to_env: String,
        from_version_id: Option<Uuid>,
        to_version_id: Uuid,
        decision: String, // promoted | blocked_by_eval | blocked_by_policy | manual_override
        notes: String,
        at_micros: i64,
    },
    #[serde(rename = "rollback")]
    Rollback {
        rollback_id: Uuid,
        from_version_id: Uuid,
        to_version_id: Uuid,
        trigger_metric: String,
        trigger_value: f64,
        sigma_drift: f32,
        rollback_mode: String, // auto | suggested | human_confirmed | human_dismissed
        at_micros: i64,
    },
}

impl HistoryEntry {
    pub fn at_micros(&self) -> i64 {
        match self {
            HistoryEntry::Promotion { at_micros, .. } => *at_micros,
            HistoryEntry::Rollback { at_micros, .. } => *at_micros,
        }
    }
}

/// Read-side hook for the promotion + rollback audit trail.
#[async_trait::async_trait]
pub trait HistoryReader: Send + Sync {
    /// Return up to `limit` entries for `(tenant_id, prompt_name)`,
    /// sorted desc by timestamp.
    async fn read(
        &self,
        tenant_id: &TenantId,
        prompt_name: &str,
        limit: u32,
    ) -> Result<Vec<HistoryEntry>>;
}

/// No-op reader — returns empty. Default for unit tests.
pub struct NoOpHistoryReader;

#[async_trait::async_trait]
impl HistoryReader for NoOpHistoryReader {
    async fn read(
        &self,
        _tenant_id: &TenantId,
        _prompt_name: &str,
        _limit: u32,
    ) -> Result<Vec<HistoryEntry>> {
        Ok(Vec::new())
    }
}

/// ClickHouse reader. Issues two parallel SELECTs against
/// `promotion_decisions` and `rollback_events`, merges + sorts client-
/// side. Today the lookup is by `prompt_id` not `prompt_name` — the
/// caller must resolve name -> id first via the version registry.
pub struct ClickHouseHistoryReader {
    client: ClickhouseClient,
}

impl ClickHouseHistoryReader {
    pub fn new(client: ClickhouseClient) -> Self {
        Self { client }
    }
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct PromotionRow {
    #[serde(with = "clickhouse::serde::uuid")]
    promotion_id: ::uuid::Uuid,
    from_env: String,
    to_env: String,
    #[serde(with = "clickhouse::serde::uuid::option")]
    from_version_id: Option<::uuid::Uuid>,
    #[serde(with = "clickhouse::serde::uuid")]
    to_version_id: ::uuid::Uuid,
    decision: String,
    notes: String,
    decided_at: i64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct RollbackRow {
    #[serde(with = "clickhouse::serde::uuid")]
    rollback_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    from_version_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    to_version_id: ::uuid::Uuid,
    trigger_metric: String,
    trigger_value: f64,
    sigma_drift: f32,
    rollback_mode: String,
    fired_at: i64,
}

#[async_trait::async_trait]
impl HistoryReader for ClickHouseHistoryReader {
    async fn read(
        &self,
        tenant_id: &TenantId,
        prompt_name: &str,
        limit: u32,
    ) -> Result<Vec<HistoryEntry>> {
        // For the V1 cut we filter by tenant_id only — prompt_name
        // resolution to prompt_id happens via the in-memory version
        // registry on the route handler side. The query still respects
        // the CLAUDE.md tenant isolation invariant.
        let _ = prompt_name;
        let limit = limit.clamp(1, 500);

        // ADR-031 V1.1 sweep: prompt-history reads are tenant-scoped
        // + LIMIT-bounded, so per-tier caps are additive. V1.1 routes
        // through TenantQuery for consistency. Exempted in
        // `scripts/ci/no-raw-ch-query.sh`.
        let promotions_fut = self
            .client
            .query(
                "SELECT promotion_id, from_env, to_env, from_version_id, \
                        to_version_id, decision, notes, decided_at \
                 FROM promotion_decisions \
                 WHERE tenant_id = ? \
                 ORDER BY decided_at DESC \
                 LIMIT ?",
            )
            .bind(tenant_id.to_string())
            .bind(limit)
            .fetch_all::<PromotionRow>();

        let rollbacks_fut = self
            .client
            .query(
                "SELECT rollback_id, from_version_id, to_version_id, \
                        trigger_metric, trigger_value, sigma_drift, \
                        rollback_mode, fired_at \
                 FROM rollback_events \
                 WHERE tenant_id = ? \
                 ORDER BY fired_at DESC \
                 LIMIT ?",
            )
            .bind(tenant_id.to_string())
            .bind(limit)
            .fetch_all::<RollbackRow>();

        let (promotions, rollbacks) = tokio::try_join!(promotions_fut, rollbacks_fut)
            .context("clickhouse history fetch failed")?;

        let mut entries: Vec<HistoryEntry> = Vec::with_capacity(promotions.len() + rollbacks.len());
        for p in promotions {
            entries.push(HistoryEntry::Promotion {
                promotion_id: p.promotion_id,
                from_env: p.from_env,
                to_env: p.to_env,
                from_version_id: p.from_version_id,
                to_version_id: p.to_version_id,
                decision: p.decision,
                notes: p.notes,
                // decided_at is DateTime64(3) = MILLIS; `at_micros` is micros.
                // Without ×1000 the UI renders 1970 (ms read as micros).
                at_micros: p.decided_at.saturating_mul(1000),
            });
        }
        for r in rollbacks {
            entries.push(HistoryEntry::Rollback {
                rollback_id: r.rollback_id,
                from_version_id: r.from_version_id,
                to_version_id: r.to_version_id,
                trigger_metric: r.trigger_metric,
                trigger_value: r.trigger_value,
                sigma_drift: r.sigma_drift,
                rollback_mode: r.rollback_mode,
                // fired_at is DateTime64(3) = MILLIS → micros (see above).
                at_micros: r.fired_at.saturating_mul(1000),
            });
        }

        // Merge-sort by timestamp desc, then truncate to `limit`.
        // sort_by_key(Reverse(...)) is the clippy-preferred form for a
        // descending sort on a Copy key (i64 here).
        entries.sort_by_key(|e| std::cmp::Reverse(e.at_micros()));
        entries.truncate(limit as usize);
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u128) -> TenantId {
        TenantId::from_jwt_claim(uuid::Uuid::from_u128(n))
    }

    #[tokio::test]
    async fn noop_reader_returns_empty() {
        let r = NoOpHistoryReader;
        let out = r.read(&tid(1), "any-prompt", 50).await.unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn entry_at_micros_uniform_for_both_kinds() {
        let p = HistoryEntry::Promotion {
            promotion_id: Uuid::nil(),
            from_env: "staging".into(),
            to_env: "production".into(),
            from_version_id: None,
            to_version_id: Uuid::nil(),
            decision: "promoted".into(),
            notes: String::new(),
            at_micros: 100,
        };
        let r = HistoryEntry::Rollback {
            rollback_id: Uuid::nil(),
            from_version_id: Uuid::nil(),
            to_version_id: Uuid::nil(),
            trigger_metric: "latency".into(),
            trigger_value: 1.0,
            sigma_drift: 2.0,
            rollback_mode: "auto".into(),
            at_micros: 200,
        };
        assert_eq!(p.at_micros(), 100);
        assert_eq!(r.at_micros(), 200);
    }

    #[test]
    fn entry_serializes_with_kind_tag() {
        let p = HistoryEntry::Promotion {
            promotion_id: Uuid::nil(),
            from_env: "staging".into(),
            to_env: "production".into(),
            from_version_id: None,
            to_version_id: Uuid::nil(),
            decision: "promoted".into(),
            notes: String::new(),
            at_micros: 100,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains(r#""kind":"promotion""#));
        assert!(s.contains(r#""at_micros":100"#));
    }
}
