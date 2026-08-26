//! `observed_tools` — the approve half of R3 rug-pull detection (/B).
//!
//! Commit A gave tenants a way to pin a tool definition. Nobody hand-authors
//! tool JSON, so pin-only would have shipped correct and unused. The gateway
//! now records the definitions it actually sees, and the dashboard offers
//! one-click approve.
//!
//! **No schema or description text is stored** — only the `def_hash` the gateway
//! computed at request time. R3 records the hash, never the tool text, and the
//! observe path does not weaken that.

use anyhow::{Result, anyhow};
use tracelane_shared::TenantId;

use crate::db::DbPool as Pool;

/// One observed definition, with whether it is currently the approved pin.
#[derive(Debug, Clone)]
pub struct ObservedTool {
    pub tool_name: String,
    pub def_hash: String,
    pub first_seen: std::time::SystemTime,
    pub last_seen: std::time::SystemTime,
    pub seen_count: i64,
    /// True when `tool_capabilities` currently pins exactly this hash.
    pub approved: bool,
}

/// Flush a batch of observations. Called off the hot path by the observer task.
///
/// Upsert semantics: `first_seen` is preserved, `last_seen` advances, and
/// `seen_count` accumulates. Under N gateway replicas each process flushes its
/// own dedupe set, so `seen_count` UNDER-counts — it is an approve-UI hint, not
/// a metric anything depends on.
///
/// # Errors
/// Propagates pool/statement errors. Fails OPEN at the call site: a failed flush
/// of *observations* must never break a request, because observing is a
/// convenience and the request is the product.
pub async fn flush_batch(pool: &Pool, rows: &[(TenantId, String, String, i64)]) -> Result<u64> {
    if rows.is_empty() {
        return Ok(0);
    }
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| anyhow!("observed_tools tx: {e}"))?;
    let stmt = tx
        .prepare(
            "INSERT INTO observed_tools (tenant_id, tool_name, def_hash, seen_count)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, tool_name, def_hash) DO UPDATE
               SET last_seen = NOW(),
                   seen_count = observed_tools.seen_count + EXCLUDED.seen_count",
        )
        .await
        .map_err(|e| anyhow!("observed_tools prepare: {e}"))?;
    let mut n = 0u64;
    for (tenant, tool, hash, count) in rows {
        n += tx
            .execute(&stmt, &[tenant.as_uuid(), tool, hash, count])
            .await
            .map_err(|e| anyhow!("observed_tools upsert: {e}"))?;
    }
    tx.commit()
        .await
        .map_err(|e| anyhow!("observed_tools commit: {e}"))?;
    Ok(n)
}

/// List a tenant's observed definitions, newest first, flagged with whether each
/// is the currently approved pin.
///
/// # Errors
/// Propagates pool/query errors — "empty" and "unreadable" must not look alike.
pub async fn list(pool: &Pool, tenant_id: &TenantId) -> Result<Vec<ObservedTool>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            "SELECT o.tool_name, o.def_hash, o.first_seen, o.last_seen, o.seen_count,
                    (tc.def_hash IS NOT NULL AND tc.def_hash = o.def_hash) AS approved
             FROM observed_tools o
             LEFT JOIN tool_capabilities tc
               ON tc.tenant_id = o.tenant_id AND tc.tool_name = o.tool_name
             WHERE o.tenant_id = $1
             ORDER BY o.last_seen DESC
             LIMIT 500",
            &[tenant_id.as_uuid()],
        )
        .await
        .map_err(|e| anyhow!("observed_tools list: {e}"))?;
    Ok(rows
        .iter()
        .map(|r| ObservedTool {
            tool_name: r.get(0),
            def_hash: r.get(1),
            first_seen: r.get(2),
            last_seen: r.get(3),
            seen_count: r.get(4),
            approved: r.get(5),
        })
        .collect())
}

/// Approve an observed definition — pin it.
///
/// **The two security properties of this feature are enforced by this one
/// statement, structurally rather than by validation:**
///
/// 1. **The pinned hash can only be one WE computed.** The value written is
///    `o.def_hash`, SELECTed from `observed_tools` — never the caller's
///    parameter. `$3` is only a *selector*. A caller naming a hash the gateway
///    never observed matches no row, writes nothing, and gets `Ok(false)` →
///    404. There is no code path by which a client-supplied hash becomes a pin.
///
/// 2. **Approve can never move `caps`.** The INSERT writes `caps = 0` for a
///    brand-new tool, and the `DO UPDATE` touches only `def_hash` — so an
///    existing owner-set `caps` is preserved and no caller can raise or lower it
///    through this path. That matters because lowering `caps` to 0 disables the
///    R4 taint detection protecting the tool just as effectively as raising it
///    grants a false sanction (/A).
///
/// Returns whether a pin was written.
///
/// # Errors
/// Propagates pool/statement errors. Fails CLOSED — a failed approve must never
/// be reported as success, or a tenant believes a tool is protected when it is
/// not.
pub async fn approve(
    pool: &Pool,
    tenant_id: &TenantId,
    tool_name: &str,
    def_hash: &str,
) -> Result<bool> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let n = client
        .execute(
            "INSERT INTO tool_capabilities (tenant_id, tool_name, caps, def_hash)
             SELECT o.tenant_id, o.tool_name, 0, o.def_hash
             FROM observed_tools o
             WHERE o.tenant_id = $1 AND o.tool_name = $2 AND o.def_hash = $3
             ON CONFLICT (tenant_id, tool_name) DO UPDATE
               SET def_hash = EXCLUDED.def_hash,
                   updated_at = NOW()",
            &[tenant_id.as_uuid(), &tool_name, &def_hash],
        )
        .await
        .map_err(|e| anyhow!("observed_tools approve: {e}"))?;
    Ok(n > 0)
}
