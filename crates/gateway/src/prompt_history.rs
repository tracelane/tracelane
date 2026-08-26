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
        // FIXED 2026-08-20 (B-261 P1). `/v1/prompts/{name}/history` used to
        // discard the name and return the tenant's ENTIRE promotion and rollback
        // history labelled as one prompt's. Tenant isolation was never affected
        // — both queries bind `tenant_id` — so it was wrong DATA, not a leak.
        //
        // THE `ponytail:` MARKER THAT STOOD HERE IS REMOVED BECAUSE ITS CEILING
        // WAS NOT REAL, which is the only sanctioned reason to remove one
        // (CLAUDE.md rule 8). It claimed `rollback_events` "has no prompt
        // dimension at all". It has one, reachable in a single hop: its
        // `prompt_id` column stores the VERSION id, and `prompt_versions` maps
        // `prompt_version_id -> prompt_name`. Verified against prod before
        // touching it — `promotion_decisions.prompt_name` exists and is
        // non-empty on 6 of 6 rows, and both join columns are present.
        //
        // The marker's REASONING was sound and is preserved as the shape of the
        // fix: filtering one half and not the other yields a page that looks
        // filtered and is not, which is worse than one honestly unfiltered. So
        // both halves filter, or neither does — pinned by
        // `both_history_queries_filter_on_prompt_name`.
        let limit = limit.clamp(1, 500);

        // ADR-031 V1.1 sweep: prompt-history reads are tenant-scoped
        // + LIMIT-bounded, so per-tier caps are additive. V1.1 routes
        // through TenantQuery for consistency. Exempted in
        // `scripts/ci/no-raw-ch-query.sh`.
        let promotions_fut = self
            .client
            .query(PROMOTIONS_SQL)
            .bind(tenant_id.to_string())
            .bind(prompt_name)
            .bind(limit)
            .fetch_all::<PromotionRow>();

        let rollbacks_fut = self
            .client
            .query(ROLLBACKS_SQL)
            .bind(tenant_id.to_string())
            .bind(tenant_id.to_string())
            .bind(prompt_name)
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

/// Both history queries, as named constants **so a test can assert the invariant
/// that broke this endpoint**: filter BOTH halves on the prompt name, or neither.
///
/// `/v1/prompts/{name}/history` shipped ignoring `{name}` entirely and returning
/// the tenant's whole timeline labelled as one prompt's. The `ponytail:` marker
/// that recorded it argued — correctly — that filtering one half and leaving the
/// other unfiltered is WORSE than an honestly unfiltered page, because it looks
/// filtered. That asymmetry is the regression worth pinning, and an inline string
/// literal cannot be inspected by a test.
const PROMOTIONS_SQL: &str = "SELECT promotion_id, from_env, to_env, from_version_id, \
        to_version_id, decision, notes, decided_at \
 FROM promotion_decisions \
 WHERE tenant_id = ? AND prompt_name = ? \
 ORDER BY decided_at DESC \
 LIMIT ?";

/// `rollback_events` carries no `prompt_name` of its own — its `prompt_id` is the
/// VERSION id (a documented B1 proxy), so the name is one hop away through
/// `prompt_versions`.
///
/// **The subquery is tenant-scoped TOO, not just the outer query.** An unscoped
/// inner `SELECT` would let another tenant's version id match and pull their
/// rollback rows into this tenant's page — that is how adding a filter turns into
/// a leak, and it is the same object-ownership axis as TRAPS §39.
const ROLLBACKS_SQL: &str = "SELECT rollback_id, from_version_id, to_version_id, \
        trigger_metric, trigger_value, sigma_drift, \
        rollback_mode, fired_at \
 FROM rollback_events \
 WHERE tenant_id = ? AND prompt_id IN ( \
     SELECT prompt_version_id FROM prompt_versions \
     WHERE tenant_id = ? AND prompt_name = ? \
 ) \
 ORDER BY fired_at DESC \
 LIMIT ?";

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u128) -> TenantId {
        TenantId::from_jwt_claim(uuid::Uuid::from_u128(n))
    }

    /// B-261 P1. `/v1/prompts/{name}/history` shipped ignoring `{name}` and
    /// returning the tenant's WHOLE promotion+rollback timeline labelled as one
    /// prompt's.
    ///
    /// **The invariant is symmetry, not presence.** The `ponytail:` marker that
    /// recorded the defect argued — correctly — that filtering one half and
    /// leaving the other unfiltered is WORSE than an honestly unfiltered page,
    /// because it then LOOKS filtered. So this asserts BOTH queries carry the
    /// name predicate; a future edit that drops it from either one fails here.
    ///
    /// Falsified before it was trusted: deleting `AND prompt_name = ?` from
    /// `PROMOTIONS_SQL` fails on the promotions assertion, and removing the
    /// subquery from `ROLLBACKS_SQL` fails on the rollbacks one.
    #[test]
    fn both_history_queries_filter_on_prompt_name() {
        assert!(
            PROMOTIONS_SQL.contains("prompt_name = ?"),
            "promotion_decisions must filter on the prompt name — without it \
             /history returns the tenant's entire timeline"
        );
        assert!(
            ROLLBACKS_SQL.contains("prompt_name = ?"),
            "rollback_events must ALSO filter on the prompt name (via the \
             prompt_versions hop) — a half-filtered page is worse than an \
             unfiltered one because it looks filtered"
        );
        // The rollback hop reaches another table, so its subquery must be
        // tenant-scoped IN ITS OWN RIGHT. An unscoped inner SELECT would match
        // another tenant's version id and pull their rows in — a filter turning
        // into a leak (TRAPS §39, the object-ownership axis).
        let inner = ROLLBACKS_SQL
            .split("prompt_id IN (")
            .nth(1)
            .expect("rollback query must reach prompt_versions through a subquery");
        assert!(
            inner.contains("tenant_id = ?"),
            "the prompt_versions subquery must bind tenant_id itself, not rely \
             on the outer query's — otherwise adding this filter opens a \
             cross-tenant read"
        );
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
