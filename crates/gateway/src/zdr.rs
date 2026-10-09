//! `GWY-49` — zero-data-retention routing (slice 1: prune + refuse; no attestation yet).
//!
//! A request that carries `x-tracelane-zdr: required` may only reach a provider whose
//! data-handling capability, per the Neon reference table `provider_capabilities`
//! (seeded from `apps/web/db/provider_capabilities.v1.json`, CLAUDE.md §23), is
//! `default` — no retention, no training, for every account. `enterprise` (a ZDR mode the
//! customer's account must hold — ADR-079 §2) is NOT eligible until the customer can declare that
//! contract on their key (spec §9 Q2, slice 2); `none` never is.
//!
//! **Fail direction: CLOSED, everywhere.** No table, no control plane, a failed load,
//! an unknown provider — all read as "not eligible", and a constrained request is
//! refused (`400 zdr_unsatisfiable`) rather than routed on no information. The
//! alternative — routing a regulated customer's request because a lookup failed — is
//! the one outcome this feature exists to make impossible. `# Errors` on each fn says
//! which reading applies.
//!
//! **What this does NOT do:** it does not substitute the customer's chosen model. An
//! ineligible PRIMARY is refused, not swapped for an eligible provider — under a
//! compliance constraint a silent model change is a worse surprise than a 400. The
//! failover chain (which only runs after a primary FAILURE) is pruned instead.
//!
//! The capability map is loaded like the rate card (`billing::rating::spawn_refresher`):
//! once at boot, then on `refresh_interval()`'s cadence — the SAME cadence, so the two
//! refreshers wake Neon together, not twice (B-442: a poller is a compute wake).

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::http::HeaderMap;

/// What a provider promises about the data it receives, per the reference table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zdr {
    /// Nothing promised (or nothing verified yet — every row ships this way).
    None,
    /// No retention, no training, for every account: eligible.
    Default,
    /// A ZDR mode exists but the customer's ACCOUNT must hold it (contract, approval or
    /// self-serve setting — `decisions/ADR-079-zdr-provider-policy-data.md` §2). The
    /// gateway cannot see a customer's account, so: not eligible in slice 1.
    Enterprise,
}

impl Zdr {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "default" => Some(Self::Default),
            "enterprise" => Some(Self::Enterprise),
            _ => None,
        }
    }
}

/// The loaded capability map. `loaded == false` is the fail-closed state.
#[derive(Debug, Clone, Default)]
pub struct ZdrCapabilities {
    by_provider: HashMap<String, Zdr>,
    loaded: bool,
}

impl ZdrCapabilities {
    /// No control plane, or the load failed: nothing is eligible.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::default()
    }

    /// Build from rows — the pure half `load` and the tests share.
    #[must_use]
    pub fn from_rows(rows: impl IntoIterator<Item = (String, String)>) -> Self {
        let by_provider = rows
            .into_iter()
            .filter_map(|(pid, zdr)| Zdr::parse(&zdr).map(|z| (pid, z)))
            .collect();
        Self {
            by_provider,
            loaded: true,
        }
    }

    /// Read the table. `# Errors`: pool or query failure — the caller keeps the
    /// previous map (or `unavailable()`), which is the fail-CLOSED reading.
    pub async fn load(pool: &crate::db::DbPool) -> anyhow::Result<Self> {
        let client = pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("provider_capabilities pool: {e}"))?;
        let rows = client
            .query("SELECT provider_id, zdr FROM provider_capabilities", &[])
            .await
            .map_err(|e| anyhow::anyhow!("provider_capabilities query: {e}"))?;
        Ok(Self::from_rows(
            rows.iter()
                .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1))),
        ))
    }

    /// THE decision. `true` only for a provider the table marks `default`. An
    /// unknown provider, `none`, `enterprise` (slice 1) and an unloaded map are all
    /// `false` — the fail-closed default, stated here once.
    #[must_use]
    pub fn eligible(&self, provider_id: &str) -> bool {
        self.loaded && self.by_provider.get(provider_id) == Some(&Zdr::Default)
    }

    /// For `/health`: whether the table has been read at all.
    #[must_use]
    pub fn loaded(&self) -> bool {
        self.loaded
    }

    /// For `/health`: how many providers are `default` — a reader's one-glance
    /// answer to "is any ZDR routing possible on this deployment".
    #[must_use]
    pub fn default_count(&self) -> usize {
        self.by_provider
            .values()
            .filter(|z| **z == Zdr::Default)
            .count()
    }
}

/// The request's constraint, from `x-tracelane-zdr`. A HEADER, deliberately: a body
/// field would reach the provider and change the request bytes the ledger hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constraint {
    Required,
}

/// Parse the header. `Ok(None)` = absent (today's behaviour); `Ok(Some(Required))`;
/// `Err(value)` = present with a value this gateway does not understand — the caller
/// refuses with `400 invalid_zdr_constraint` BEFORE routing, because guessing what a
/// compliance header meant is not an option. `# Errors`: the unrecognised value.
pub fn constraint_from_headers(headers: &HeaderMap) -> Result<Option<Constraint>, String> {
    let Some(v) = headers.get("x-tracelane-zdr") else {
        return Ok(None);
    };
    let s = v.to_str().map_err(|_| "<non-ascii>".to_string())?.trim();
    match s.to_ascii_lowercase().as_str() {
        "required" => Ok(Some(Constraint::Required)),
        other => Err(other.to_string()),
    }
}

static HEALTH_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static HEALTH_DEFAULT_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Unix seconds of the last SUCCESSFUL load; 0 = never. With `refresh_failures` this is
/// the staleness signal: `capabilities_loaded` stays true across a failing refresh
/// (the previous map keeps serving — stale eligibility beats none), so an operator
/// reads "loaded, but last at T and N refreshes failed since".
static HEALTH_LAST_LOADED_UNIX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Consecutive refresh failures since the last successful load; reset to 0 on success.
static HEALTH_REFRESH_FAILURES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn store(caps: &ArcSwap<ZdrCapabilities>, loaded: ZdrCapabilities) {
    use std::sync::atomic::Ordering::Relaxed;
    HEALTH_LOADED.store(loaded.loaded(), Relaxed);
    HEALTH_DEFAULT_COUNT.store(loaded.default_count(), Relaxed);
    HEALTH_LAST_LOADED_UNIX.store(
        u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
        Relaxed,
    );
    HEALTH_REFRESH_FAILURES.store(0, Relaxed);
    caps.store(Arc::new(loaded));
}

fn note_load_failure() {
    HEALTH_REFRESH_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// `/health.zdr`: has the capability table been read, how many providers are
/// `default`, when the last successful read was, and how many refreshes have failed
/// since — an operator's one-glance answer to "can any ZDR request succeed here, and
/// is that answer current". `capabilities_loaded: false` means every constrained
/// request is being refused (fail-closed); `refresh_failures > 0` means the map that
/// IS serving is older than `last_loaded_unix` says.
#[must_use]
pub fn health_json() -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    serde_json::json!({
        "capabilities_loaded": HEALTH_LOADED.load(Relaxed),
        "default_providers": HEALTH_DEFAULT_COUNT.load(Relaxed),
        "last_loaded_unix": HEALTH_LAST_LOADED_UNIX.load(Relaxed),
        "refresh_failures": HEALTH_REFRESH_FAILURES.load(Relaxed),
    })
}

/// Load once, then refresh on the rate card's cadence (one Neon wake for both).
pub async fn spawn_refresher(pool: crate::db::DbPool, caps: Arc<ArcSwap<ZdrCapabilities>>) {
    match ZdrCapabilities::load(&pool).await {
        Ok(loaded) => store(&caps, loaded),
        Err(e) => {
            note_load_failure();
            tracing::warn!(error = %e, "initial provider_capabilities load failed; ZDR routing is fail-closed (nothing eligible) until a refresh succeeds")
        }
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(crate::billing::rating::refresh_interval());
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match ZdrCapabilities::load(&pool).await {
                Ok(loaded) => store(&caps, loaded),
                Err(e) => {
                    note_load_failure();
                    tracing::warn!(
                        error = %e,
                        "provider_capabilities refresh failed; keeping the previous map"
                    )
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(rows: &[(&str, &str)]) -> ZdrCapabilities {
        ZdrCapabilities::from_rows(
            rows.iter()
                .map(|(p, z)| ((*p).to_string(), (*z).to_string())),
        )
    }

    /// Spec §7 proof 1 — THE decision, every arm: `default` alone is eligible;
    /// `none`, `enterprise`, an unknown provider and an unloaded map are not.
    #[test]
    fn only_default_is_eligible_and_an_unloaded_map_makes_nothing_eligible() {
        let c = caps(&[
            ("openai", "none"),
            ("vertex", "default"),
            ("anthropic", "enterprise"),
            ("junk", "not-a-level"),
        ]);
        assert!(c.eligible("vertex"));
        assert!(!c.eligible("openai"), "none is never eligible");
        assert!(
            !c.eligible("anthropic"),
            "enterprise needs the slice-2 declaration"
        );
        assert!(
            !c.eligible("junk"),
            "an unparseable level is dropped, never eligible"
        );
        assert!(
            !c.eligible("never-heard-of-it"),
            "unknown provider → not eligible"
        );
        assert_eq!(c.default_count(), 1);
        assert!(c.loaded());
        let none = ZdrCapabilities::unavailable();
        assert!(!none.loaded());
        assert!(
            !none.eligible("vertex"),
            "fail-CLOSED: no table → nothing eligible"
        );
        assert_eq!(none.default_count(), 0);
    }

    /// Spec §7 proof 2 — the header's three outcomes.
    #[test]
    fn header_parses_required_rejects_garbage_and_absent_is_none() {
        let mut h = HeaderMap::new();
        assert_eq!(constraint_from_headers(&h), Ok(None));
        h.insert("x-tracelane-zdr", " Required ".parse().unwrap());
        assert_eq!(constraint_from_headers(&h), Ok(Some(Constraint::Required)));
        h.insert("x-tracelane-zdr", "please".parse().unwrap());
        assert_eq!(constraint_from_headers(&h), Err("please".to_string()));
        h.insert("x-tracelane-zdr", "".parse().unwrap());
        assert_eq!(constraint_from_headers(&h), Err(String::new()));
    }
}
