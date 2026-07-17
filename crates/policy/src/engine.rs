//! Cedar policy engine scaffold — NOT wired into the gateway in V1.
//!
//! This is a placeholder for a future per-tenant Cedar authorization layer.
//! It has **no call sites** in V1 (V1 per-tenant gating is enforced by
//! Postgres `workspace_entitlements`, not by this engine). Until the Cedar
//! policy set is actually loaded and evaluated, every method **fails
//! closed** — it returns `PolicyDecision::Deny`, never `Allow`. This is
//! deliberate: a security authorization control must never default-allow.
//! Wiring this engine in before the real evaluation lands would (correctly)
//! deny every request, surfacing the gap loudly rather than silently
//! authorizing everything.
//!
//! Full implementation will use the `cedar-policy` crate (Apache 2.0, from
//! AWS). Policies are loaded from Postgres (`tracelane.tenant_policies`) at
//! startup and hot-reloaded every 60s via an ArcSwap.
//!
//! Policy example (Cedar):
//! ```cedar
//! permit(
//!   principal == Tenant::"acme",
//!   action == Action::"call_provider",
//!   resource == Provider::"anthropic"
//! ) when {
//!   context.model_tier == "standard"
//! };
//! ```

use anyhow::Result;
use tracing::instrument;

use tracelane_shared::TenantId;

/// Result of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: &'static str },
}

/// Cedar policy engine.
///
/// Thread-safe — clone freely; the inner state uses ArcSwap.
#[derive(Clone, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate whether a tenant is allowed to call the given provider/model.
    ///
    /// **Fails closed.** Until the Cedar policy set is loaded and evaluated
    /// (not in V1), this returns `PolicyDecision::Deny`. It is intentionally
    /// never `Allow` — a half-wired authorization control must not
    /// default-allow. There are no V1 call sites; V1 per-tenant gating is
    /// `workspace_entitlements` (Postgres), not this engine.
    ///
    /// # Errors
    /// Returns `Err` only once real evaluation is implemented and the policy
    /// store is unavailable. The fail-closed default is `Deny`, never a
    /// fall-back `Allow`.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, provider = %provider, model = %model))]
    pub async fn evaluate_gateway_call(
        &self,
        tenant_id: &TenantId,
        provider: &str,
        model: &str,
    ) -> Result<PolicyDecision> {
        let _ = (tenant_id, provider, model);
        // Cedar policy-set evaluation is not implemented in V1. Fail closed:
        // never default-allow a request through an unimplemented authz layer.
        Ok(PolicyDecision::Deny {
            reason: "policy engine not implemented (V1 uses workspace_entitlements); fail-closed",
        })
    }

    /// Evaluate whether a tenant is allowed to export data.
    ///
    /// **Fails closed** — see [`Self::evaluate_gateway_call`]. Returns `Deny`
    /// until real Cedar evaluation lands; no V1 call sites.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, export_type = %export_type))]
    pub async fn evaluate_export(
        &self,
        tenant_id: &TenantId,
        export_type: &str,
    ) -> Result<PolicyDecision> {
        let _ = (tenant_id, export_type);
        Ok(PolicyDecision::Deny {
            reason: "policy engine not implemented (V1 uses workspace_entitlements); fail-closed",
        })
    }
}
