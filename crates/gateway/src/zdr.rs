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
//! Existing routing determines model substitution: an opted-in failover chain may
//! prune an ineligible primary (`server/chat.rs`); this module only decides whether
//! a provider's dated evidence is eligible. It does not attest provider behavior.
//!
//! The capability map is loaded like the rate card (`billing::rating::spawn_refresher`):
//! once at boot, then on `refresh_interval()`'s cadence — the SAME cadence, so the two
//! refreshers wake Neon together, not twice (B-442: a poller is a compute wake).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Duration, Utc};

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

/// Reviewed evidence lifetime, parsed once. Invalid policy fails CLOSED.
fn parse_max_age(raw: &str) -> Option<Duration> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let days = value.get("zdr_policy")?.get("max_age_days")?.as_i64()?;
    (days > 0).then(|| Duration::try_days(days)).flatten()
}

fn policy_max_age() -> Option<Duration> {
    static POLICY: OnceLock<Option<Duration>> = OnceLock::new();
    *POLICY.get_or_init(|| parse_max_age(include_str!("../translation_policy.v1.json")))
}

#[derive(Debug, Clone)]
struct Evidence {
    category: Zdr,
    verified_at: Option<DateTime<Utc>>,
}

impl Evidence {
    /// Fail CLOSED on absent, future, expired or overflowing evidence.
    fn eligible_at(&self, now: DateTime<Utc>, max_age: Option<Duration>) -> bool {
        let Some((verified, age)) = self.verified_at.zip(max_age) else {
            return false;
        };
        self.category == Zdr::Default
            && verified <= now
            && verified
                .checked_add_signed(age)
                .is_some_and(|end| now < end)
    }
}

/// The loaded capability map. Evidence expires even when refresh stops succeeding.
#[derive(Debug, Clone, Default)]
pub struct ZdrCapabilities {
    by_provider: HashMap<String, Evidence>,
    loaded: bool,
}

impl ZdrCapabilities {
    /// No control plane, or the initial load failed: nothing is eligible.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::default()
    }

    /// Legacy test fixtures explicitly supply synthetic current evidence.
    /// Production must load the actual stored metadata instead.
    #[cfg(test)]
    pub fn from_rows(rows: impl IntoIterator<Item = (String, String)>) -> Self {
        let verified = Utc::now();
        Self::from_evidence_rows(rows.into_iter().map(|(pid, category)| {
            (
                pid,
                category,
                Some("https://example.com/test-policy".to_owned()),
                Some(verified),
            )
        }))
    }

    fn from_evidence_rows(
        rows: impl IntoIterator<Item = (String, String, Option<String>, Option<DateTime<Utc>>)>,
    ) -> Self {
        let by_provider = rows
            .into_iter()
            .filter_map(|(pid, category, policy_url, verified_at)| {
                let category = Zdr::parse(&category)?;
                // Provenance only: never fetch this URL. Validate once on refresh, not per request.
                let valid_url = policy_url.as_deref().is_some_and(|raw| {
                    raw.get(..8)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
                        && reqwest::Url::parse(raw).is_ok_and(|url| {
                            url.scheme() == "https"
                                && url.host_str().is_some()
                                && url.username().is_empty()
                                && url.password().is_none()
                        })
                });
                Some((
                    pid,
                    Evidence {
                        category,
                        verified_at: verified_at.filter(|_| valid_url),
                    },
                ))
            })
            .collect();
        Self {
            by_provider,
            loaded: true,
        }
    }

    /// Read evidence through the existing refresh cache, never per request.
    ///
    /// # Errors
    /// Pool, query or decoding failures fail CLOSED: the caller retains previous
    /// evidence, whose expiry is still enforced at each eligibility decision.
    pub async fn load(pool: &crate::db::DbPool) -> anyhow::Result<Self> {
        let client = pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("provider_capabilities pool: {e}"))?;
        let rows = client
            .query(
                "SELECT provider_id, zdr, policy_url, verified_at FROM provider_capabilities",
                &[],
            )
            .await
            .map_err(|e| anyhow::anyhow!("provider_capabilities query: {e}"))?;
        let evidence = rows
            .iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?, r.try_get(3)?)))
            .collect::<Result<Vec<_>, tokio_postgres::Error>>()?;
        Ok(Self::from_evidence_rows(evidence))
    }

    /// Fail CLOSED unless default-provider evidence is complete and currently valid.
    #[must_use]
    pub fn eligible(&self, provider_id: &str) -> bool {
        self.eligible_at(provider_id, Utc::now())
    }

    fn eligible_at(&self, provider_id: &str, now: DateTime<Utc>) -> bool {
        self.loaded
            && self
                .by_provider
                .get(provider_id)
                .is_some_and(|e| e.eligible_at(now, policy_max_age()))
    }

    /// For `/health`: whether the table has been read at all, not a freshness grant.
    #[must_use]
    pub fn loaded(&self) -> bool {
        self.loaded
    }

    /// Number currently eligible. Health records this as a last-load snapshot;
    /// refusal responses calculate it at the time they are produced.
    #[must_use]
    pub fn default_count(&self) -> usize {
        self.default_count_at(Utc::now())
    }

    fn default_count_at(&self, now: DateTime<Utc>) -> usize {
        self.by_provider
            .values()
            .filter(|e| e.eligible_at(now, policy_max_age()))
            .count()
    }

    fn oldest_verified_at(&self) -> Option<DateTime<Utc>> {
        self.by_provider
            .values()
            .filter(|e| e.category == Zdr::Default)
            .filter_map(|e| e.verified_at)
            .min()
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
    if headers.get_all("x-tracelane-zdr").iter().count() > 1 {
        return Err("multiple constraints".to_owned());
    }
    let Some(v) = headers.get("x-tracelane-zdr") else {
        return Ok(None);
    };
    let s = v.to_str().map_err(|_| "<non-ascii>".to_string())?.trim();
    match s.to_ascii_lowercase().as_str() {
        "required" => Ok(Some(Constraint::Required)),
        other => Err(other.to_string()),
    }
}

/// Required binding for every admitted dispatch family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ZdrBinding {
    Gated,
    RefuseContentWrites,
    Opaque,
}

/// Validate the constraint before any auxiliary or provider dispatch. Fail closed.
pub(crate) fn route_constraint(
    headers: &HeaderMap,
    binding: ZdrBinding,
) -> Result<Option<Constraint>, crate::admission::ControlDenial> {
    let constraint = constraint_from_headers(headers)
        .map_err(|_| denial("invalid_zdr_constraint", "invalid_constraint"))?;
    if constraint.is_some() {
        match binding {
            ZdrBinding::RefuseContentWrites => {
                return Err(denial("zdr_unsatisfiable", "endpoint_retains"));
            }
            ZdrBinding::Opaque => return Err(denial("zdr_unsatisfiable", "passthrough_opaque")),
            ZdrBinding::Gated => {}
        }
    }
    Ok(constraint)
}

/// Provider check for companion and realtime dispatch, before resolving credentials.
pub(crate) fn gate(
    headers: &HeaderMap,
    capabilities: &ZdrCapabilities,
    provider: &str,
    binding: ZdrBinding,
) -> Result<Option<Constraint>, crate::admission::ControlDenial> {
    let constraint = route_constraint(headers, binding)?;
    if constraint.is_some() && !capabilities.eligible(provider) {
        return Err(denial("zdr_unsatisfiable", "provider_ineligible"));
    }
    Ok(constraint)
}

pub(crate) fn denial(code: &'static str, reason: &'static str) -> crate::admission::ControlDenial {
    crate::admission::ControlDenial {
        status: 400,
        code,
        message: "the requested zero-retention constraint cannot be satisfied".to_owned(),
        detail: vec![("reason", serde_json::json!(reason))],
        retry_after_secs: None,
    }
}

static HEALTH_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static HEALTH_DEFAULT_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Oldest complete default-provider evidence in the last loaded snapshot;
/// i64::MIN means absent (outside the chrono timestamp range).
static HEALTH_OLDEST_VERIFIED_UNIX: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(i64::MIN);
/// Unix seconds of the last SUCCESSFUL load; 0 = never. With `refresh_failures` this is
/// the staleness signal: `capabilities_loaded` stays true across a failing refresh
/// (cached evidence remains subject to its original expiry), so an operator
/// reads "loaded, but last at T and N refreshes failed since".
static HEALTH_LAST_LOADED_UNIX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Consecutive refresh failures since the last successful load; reset to 0 on success.
static HEALTH_REFRESH_FAILURES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn store(caps: &ArcSwap<ZdrCapabilities>, loaded: ZdrCapabilities) {
    use std::sync::atomic::Ordering::Relaxed;
    HEALTH_LOADED.store(loaded.loaded(), Relaxed);
    HEALTH_DEFAULT_COUNT.store(loaded.default_count(), Relaxed);
    HEALTH_OLDEST_VERIFIED_UNIX.store(
        loaded
            .oldest_verified_at()
            .map_or(i64::MIN, |date| date.timestamp()),
        Relaxed,
    );
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

/// `/health.zdr`: last-load status and evidence provenance. `default_providers` is
/// explicitly a LOAD SNAPSHOT, not a current eligibility grant. Callers must use
/// `eligible` for routing: time may expire evidence without a successful reload.
/// The oldest verification date and policy interval expose that distinction.
#[must_use]
pub fn health_json() -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let oldest = HEALTH_OLDEST_VERIFIED_UNIX.load(Relaxed);
    serde_json::json!({
        "oldest_verified_at_unix": (oldest != i64::MIN).then_some(oldest),
        "policy_max_age_seconds": policy_max_age().map(|age| age.num_seconds()),
        "default_providers_is_load_snapshot": true,
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
    fn og38_malformed_constraint_refused() {
        let mut headers = HeaderMap::new();
        headers.append("x-tracelane-zdr", "required".parse().unwrap());
        headers.append("x-tracelane-zdr", "optional".parse().unwrap());
        assert!(
            constraint_from_headers(&headers).is_err(),
            "conflicting constraints must be refused"
        );
    }

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

pub(crate) fn bindings() -> serde_json::Value {
    use crate::admission::Route;
    macro_rules! rows { ($($route:ty),* $(,)?) => { serde_json::json!([$({"route": <$route>::NAME,"binding":<$route>::ZDR}),*]) }; }
    rows!(
        crate::admission::Chat,
        crate::admission::Embeddings,
        crate::anthropic_messages::Messages,
        crate::openai_responses::Responses,
        crate::gemini_native::Gemini,
        crate::realtime::Realtime,
        crate::files_batches::FilesUpload,
        crate::files_batches::BatchesCreate,
        crate::passthrough::Passthrough,
        crate::media_routes::ImagesGenerations,
        crate::media_routes::ImagesEdits,
        crate::media_routes::AudioSpeech,
        crate::media_routes::AudioTranscriptions,
        crate::media_routes::AudioTranslations,
        crate::media_routes::Moderations,
        crate::media_routes::Rerank
    )
}

#[cfg(test)]
mod controls_tests {
    use super::*;
    fn required() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-tracelane-zdr", "required".parse().unwrap());
        h
    }
    #[test]
    fn og38_absent_constraint_preserves_dispatch() {
        for b in [
            ZdrBinding::Gated,
            ZdrBinding::Opaque,
            ZdrBinding::RefuseContentWrites,
        ] {
            assert!(
                gate(
                    &HeaderMap::new(),
                    &ZdrCapabilities::unavailable(),
                    "unknown",
                    b
                )
                .is_ok()
            );
        }
    }
    #[test]
    fn og38_default_provider_is_eligible() {
        let caps = ZdrCapabilities::from_rows([("test".to_owned(), "default".to_owned())]);
        assert_eq!(
            gate(&required(), &caps, "test", ZdrBinding::Gated).unwrap(),
            Some(Constraint::Required)
        );
    }
    #[test]
    fn og38_realtime_refuses_ineligible_provider() {
        assert_eq!(
            gate(
                &required(),
                &ZdrCapabilities::unavailable(),
                "test",
                ZdrBinding::Gated
            )
            .unwrap_err()
            .code,
            "zdr_unsatisfiable"
        );
    }
    #[test]
    fn og38_files_refuse_required() {
        assert_eq!(
            route_constraint(&required(), ZdrBinding::RefuseContentWrites)
                .unwrap_err()
                .detail[0]
                .1,
            serde_json::json!("endpoint_retains")
        );
    }
    #[test]
    fn og38_passthrough_refuses_required() {
        assert_eq!(
            route_constraint(&required(), ZdrBinding::Opaque)
                .unwrap_err()
                .detail[0]
                .1,
            serde_json::json!("passthrough_opaque")
        );
    }
    #[test]
    fn og38_enterprise_is_not_default() {
        let c = ZdrCapabilities::from_rows([("test".to_owned(), "enterprise".to_owned())]);
        assert!(gate(&required(), &c, "test", ZdrBinding::Gated).is_err());
    }
}

#[cfg(test)]
mod freshness_tests;
