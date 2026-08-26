//! `tool_capabilities` writes — the pin side of R3 rug-pull detection.
//!
//! The READ side already existed and is wired: `guardrail::registry_loader`'s
//! `pg_registry_resolver` loads `(tool_name, caps, def_hash)` per tenant and
//! calls `CapabilityRegistry::register_pinned`, and `R3Pinning` compares each
//! request's `def_hash` against the pin. What was missing — the whole of
//! is a way for a tenant to CREATE a pin. Without one the rail is correct and
//! inert: nothing is pinned, so nothing can drift.
//!
//! Tenant isolation: every statement filters on `tenant_id = $1` from the
//! resolved tenant UUID (never an `org_id`, never a request body).

use anyhow::{Result, anyhow};
use tracelane_shared::TenantId;

use crate::db::DbPool as Pool;

/// One pinned tool as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPin {
    pub tool_name: String,
    /// `CapabilitySet` bits (0..=7). The table CHECKs this range.
    pub caps: i16,
    /// Hex blake3 of the approved definition, or `None` for a caps-only row.
    pub def_hash: Option<String>,
}

/// Pin (or re-pin) a tool definition for a tenant.
///
/// `def_hash` is computed by the CALLER from the submitted definition via
/// `guardrail::capability::def_hash` — never supplied by the client. See
/// `guardrail::tool_pins_api` for why that is load-bearing rather than stylistic.
///
/// # Errors
/// Fails CLOSED: any pool/statement error propagates. A failed pin must not be
/// reported as success, or a tenant believes a tool is protected when it is not.
pub async fn upsert(
    pool: &Pool,
    tenant_id: &TenantId,
    tool_name: &str,
    caps: i16,
    def_hash: Option<&str>,
) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "INSERT INTO tool_capabilities (tenant_id, tool_name, caps, def_hash)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, tool_name) DO UPDATE
               SET caps = EXCLUDED.caps,
                   def_hash = EXCLUDED.def_hash,
                   updated_at = NOW()",
            &[tenant_id.as_uuid(), &tool_name, &caps, &def_hash],
        )
        .await
        .map_err(|e| anyhow!("tool_capabilities upsert: {e}"))?;
    Ok(())
}

/// Pin a definition **without touching `caps`** — the API-key path.
///
///  follow-up: `caps` is what R4 lethal-trifecta reasons about, so ANY
/// change to it is security-relevant *in both directions*. Raising bits can make
/// an exfiltration path look sanctioned; **lowering them to 0 silently disables
/// the taint detection that was protecting the tool.** A caller who is not a
/// verified owner therefore may not move `caps` at all — not up, not down.
///
/// On INSERT this stores `caps = 0` (a brand-new tool has no granted
/// capabilities). On CONFLICT it updates only `def_hash`, leaving whatever an
/// owner previously set.
///
/// # Errors
/// Fails CLOSED — a failed pin must never be reported as success.
pub async fn upsert_definition_only(
    pool: &Pool,
    tenant_id: &TenantId,
    tool_name: &str,
    def_hash: &str,
) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "INSERT INTO tool_capabilities (tenant_id, tool_name, caps, def_hash)
             VALUES ($1, $2, 0, $3)
             ON CONFLICT (tenant_id, tool_name) DO UPDATE
               SET def_hash = EXCLUDED.def_hash,
                   updated_at = NOW()",
            &[tenant_id.as_uuid(), &tool_name, &def_hash],
        )
        .await
        .map_err(|e| anyhow!("tool_capabilities upsert_definition_only: {e}"))?;
    Ok(())
}

/// List a tenant's pinned tools.
///
/// # Errors
/// Propagates pool/query errors — an empty list and an unreadable table must
/// not be indistinguishable to the caller.
pub async fn list(pool: &Pool, tenant_id: &TenantId) -> Result<Vec<ToolPin>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            "SELECT tool_name, caps, def_hash FROM tool_capabilities
             WHERE tenant_id = $1 ORDER BY tool_name",
            &[tenant_id.as_uuid()],
        )
        .await
        .map_err(|e| anyhow!("tool_capabilities list: {e}"))?;
    Ok(rows
        .iter()
        .map(|r| ToolPin {
            tool_name: r.get(0),
            caps: r.get(1),
            def_hash: r.get(2),
        })
        .collect())
}

/// Remove a tenant's pin. Returns whether a row was deleted.
///
/// # Errors
/// Propagates pool/statement errors.
pub async fn delete(pool: &Pool, tenant_id: &TenantId, tool_name: &str) -> Result<bool> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let n = client
        .execute(
            "DELETE FROM tool_capabilities WHERE tenant_id = $1 AND tool_name = $2",
            &[tenant_id.as_uuid(), &tool_name],
        )
        .await
        .map_err(|e| anyhow!("tool_capabilities delete: {e}"))?;
    Ok(n > 0)
}
