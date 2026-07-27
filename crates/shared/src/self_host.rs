//! Single-tenant self-host mode — activation config + the multi-tenant hard-fail guard.
//!
//! Self-host (the `$5–10 VPS / 2 GB` single-node deployment) is inherently
//! **single-tenant**: one operator, one workspace, one set of provider keys.
//! The multi-tenant `tenant_id`-spoof threat that SPIFFE mTLS guards against on
//! the hosted ingest path (any peer could assert any tenant) cannot occur when
//! there is exactly one tenant. This module resolves that mode from the
//! environment and is consumed by BOTH the gateway (auth) and ingest (SPIRE
//! bail skip + fixed-tenant span stamping).
//!
//! ## Activation (opt-in, both binaries)
//! - `TRACELANE_SELF_HOST=1` (or `true`) — explicit operator opt-in, AND
//! - `TRACELANE_SINGLE_TENANT_ID=<uuid>` — the one tenant every span is stamped with.
//!
//! ## The guard (load-bearing — keeps this un-flippable in hosted)
//! When `TRACELANE_SELF_HOST=1`, [`resolve`] **refuses to start** (returns
//! `Err`) if any multi-tenant / hosted signal is present ([`MULTI_TENANT_SIGNAL_ENVS`]:
//! a control-plane Postgres, WorkOS identity, or a SPIRE socket) or if the
//! single tenant id is unset / malformed. The hosted deployment always sets at
//! least one of those, so single-tenant self-host can never be enabled there —
//! the SPIRE-mandatory ingest path stays intact for hosted. See ADR-067.

use crate::TenantId;
use uuid::Uuid;

/// Explicit opt-in flag for single-tenant self-host mode.
pub const SELF_HOST_ENV: &str = "TRACELANE_SELF_HOST";

/// The one tenant id every span is stamped with in single-tenant self-host mode.
pub const SINGLE_TENANT_ID_ENV: &str = "TRACELANE_SINGLE_TENANT_ID";

/// Env keys whose (non-empty) presence signals a MULTI-tenant / hosted
/// deployment. If ANY is set while `TRACELANE_SELF_HOST=1`, [`resolve`] hard-
/// fails — single-tenant self-host must never coexist with the hosted control
/// plane (which is where a real multi-tenant `tenant_id`-spoof risk lives).
///
/// - `POSTGRES_URL` / `PGHOST` — the entitlements / tenants control plane (hosted).
/// - `WORKOS_CLIENT_ID` — multi-tenant identity (hosted).
/// - `TRACELANE_SPIRE_SOCKET` — SPIFFE mTLS ingest (the multi-tenant ingest auth
///   this mode deliberately replaces; refusing here means the two auth models
///   can never be half-enabled at once).
pub const MULTI_TENANT_SIGNAL_ENVS: &[&str] = &[
    "POSTGRES_URL",
    "PGHOST",
    "WORKOS_CLIENT_ID",
    "TRACELANE_SPIRE_SOCKET",
];

/// Resolved single-tenant self-host configuration. Only constructible via
/// [`resolve`] / [`from_env`], both of which enforce the multi-tenant guard —
/// so holding a `SelfHostConfig` is proof the guard passed.
#[derive(Debug, Clone)]
pub struct SelfHostConfig {
    tenant_id: TenantId,
}

impl SelfHostConfig {
    /// The one tenant every ingested span is stamped with, and that every
    /// gateway request authenticates as.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Why single-tenant self-host mode refused to start. Every variant is a
/// fail-closed startup error — the process must not boot in an ambiguous or
/// hosted configuration.
#[derive(Debug, thiserror::Error)]
pub enum SelfHostError {
    /// A multi-tenant / hosted signal was present alongside `TRACELANE_SELF_HOST=1`.
    #[error(
        "TRACELANE_SELF_HOST=1 (single-tenant self-host) refuses to start: \
         multi-tenant/hosted signal(s) present: {0}. This mode disables SPIRE mTLS \
         and stamps ONE fixed tenant on every span, so it must never run in a \
         hosted/multi-tenant deployment. Unset the listed variable(s), or run the \
         hosted (SPIRE-mandatory) path by leaving TRACELANE_SELF_HOST unset."
    )]
    MultiTenantSignal(String),

    /// `TRACELANE_SELF_HOST=1` but no `TRACELANE_SINGLE_TENANT_ID`.
    #[error(
        "TRACELANE_SELF_HOST=1 requires TRACELANE_SINGLE_TENANT_ID=<uuid> — the one \
         tenant every span is stamped with. Set it (e.g. \
         `openssl rand` a UUID, or use 00000000-0000-0000-0000-000000000001)."
    )]
    MissingTenantId,

    /// `TRACELANE_SINGLE_TENANT_ID` was set but is not a valid UUID.
    #[error("TRACELANE_SINGLE_TENANT_ID must be a valid UUID, got {0:?}")]
    InvalidTenantId(String),
}

/// Resolve single-tenant self-host mode from the process environment.
///
/// `Ok(None)` = mode disabled (the normal hosted / multi-tenant path).
/// `Ok(Some(cfg))` = single-tenant self-host active, guard passed.
/// `Err(_)` = `TRACELANE_SELF_HOST=1` but the config is ambiguous or hosted —
/// the caller MUST fail the process startup (do not fall back).
///
/// # Errors
/// Fail-closed — see [`SelfHostError`]. A multi-tenant signal, a missing tenant
/// id, or a malformed tenant id each abort startup.
pub fn from_env() -> Result<Option<SelfHostConfig>, SelfHostError> {
    resolve(|k| std::env::var(k).ok())
}

/// Core resolver with the environment lookup injected, so tests drive it
/// without mutating process env (testing.md: no env leakage across the suite).
///
/// # Errors
/// See [`from_env`].
pub fn resolve(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<SelfHostConfig>, SelfHostError> {
    let enabled = get(SELF_HOST_ENV)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    if !enabled {
        return Ok(None);
    }

    // Guard FIRST (before reading the tenant id): the security-critical check is
    // "is this actually a hosted/multi-tenant box?". A configured single tenant
    // id must never mask a hosted signal.
    let present: Vec<&str> = MULTI_TENANT_SIGNAL_ENVS
        .iter()
        .copied()
        .filter(|k| get(k).map(|v| !v.trim().is_empty()).unwrap_or(false))
        .collect();
    if !present.is_empty() {
        return Err(SelfHostError::MultiTenantSignal(present.join(", ")));
    }

    let raw = get(SINGLE_TENANT_ID_ENV)
        .map(|v| v.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(SelfHostError::MissingTenantId)?;
    let uuid = Uuid::parse_str(&raw).map_err(|_| SelfHostError::InvalidTenantId(raw.clone()))?;

    Ok(Some(SelfHostConfig {
        tenant_id: TenantId::from_self_host_config(uuid),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Build an env lookup from a fixed map — no process env mutation. Owns its
    /// keys/values so the returned closure has no borrow of `pairs`.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    const TID: &str = "00000000-0000-0000-0000-000000000001";

    #[test]
    fn disabled_when_flag_unset() {
        // No TRACELANE_SELF_HOST → None, even if a tenant id happens to be set.
        let cfg = resolve(env(&[(SINGLE_TENANT_ID_ENV, TID)])).unwrap();
        assert!(cfg.is_none(), "mode must be off unless explicitly opted in");
    }

    #[test]
    fn enabled_stamps_the_single_configured_tenant() {
        let cfg = resolve(env(&[(SELF_HOST_ENV, "1"), (SINGLE_TENANT_ID_ENV, TID)]))
            .unwrap()
            .expect("single-tenant self-host should activate");
        assert_eq!(cfg.tenant_id().to_string(), TID);
    }

    #[test]
    fn accepts_true_as_well_as_1() {
        let cfg = resolve(env(&[(SELF_HOST_ENV, "true"), (SINGLE_TENANT_ID_ENV, TID)])).unwrap();
        assert!(cfg.is_some());
    }

    #[test]
    fn hard_fails_without_tenant_id() {
        // Ambiguous config: opted in but no single tenant → refuse to start.
        let err = resolve(env(&[(SELF_HOST_ENV, "1")])).unwrap_err();
        assert!(matches!(err, SelfHostError::MissingTenantId));
    }

    #[test]
    fn hard_fails_on_malformed_tenant_id() {
        let err = resolve(env(&[
            (SELF_HOST_ENV, "1"),
            (SINGLE_TENANT_ID_ENV, "not-a-uuid"),
        ]))
        .unwrap_err();
        assert!(matches!(err, SelfHostError::InvalidTenantId(_)));
    }

    /// GUARD (load-bearing): every multi-tenant/hosted signal must, on its own,
    /// hard-fail single-tenant self-host — it can NEVER be flipped on in hosted.
    #[test]
    fn hard_fails_on_any_multi_tenant_signal() {
        for signal in MULTI_TENANT_SIGNAL_ENVS {
            let err = resolve(env(&[
                (SELF_HOST_ENV, "1"),
                (SINGLE_TENANT_ID_ENV, TID),
                (signal, "present"),
            ]))
            .unwrap_err();
            match err {
                SelfHostError::MultiTenantSignal(s) => {
                    assert!(
                        s.contains(signal),
                        "error must name the offending signal {signal}"
                    );
                }
                other => panic!("expected MultiTenantSignal for {signal}, got {other:?}"),
            }
        }
    }

    #[test]
    fn guard_wins_over_a_valid_tenant_id() {
        // Even a perfectly valid single tenant id must not mask a hosted signal
        // (Postgres present) — the guard fires first.
        let err = resolve(env(&[
            (SELF_HOST_ENV, "1"),
            (SINGLE_TENANT_ID_ENV, TID),
            ("POSTGRES_URL", "postgres://host/db"),
        ]))
        .unwrap_err();
        assert!(matches!(err, SelfHostError::MultiTenantSignal(_)));
    }

    #[test]
    fn empty_signal_value_is_not_a_signal() {
        // An exported-but-empty POSTGRES_URL="" must not trip the guard (docker
        // compose interpolation of an unset var yields empty, not absent).
        let cfg = resolve(env(&[
            (SELF_HOST_ENV, "1"),
            (SINGLE_TENANT_ID_ENV, TID),
            ("POSTGRES_URL", ""),
        ]))
        .unwrap();
        assert!(
            cfg.is_some(),
            "an empty hosted-signal value must not block self-host"
        );
    }
}
