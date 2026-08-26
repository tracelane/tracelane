//! B1 Prompt Router — promotion graph routing.
//!
//! Per ADR-009 and §7.4. Always compiled in V1; product
//! access is gated at runtime via `workspace_entitlements`, not a
//! `cfg(feature)` flag (CLAUDE.md bans cfg(feature) for product gating).
//! ClickHouse persistence + eval gate + auto-rollback are wired in
//! `server.rs::run` when `CLICKHOUSE_URL` is set.
//!
//! Holds the active per-`(tenant, prompt_name, env)` routing pointer in an
//! `arc_swap::ArcSwap` so reads are sub-1ms wait-free. A second `ArcSwap`
//! holds the version registry — `prompt_version_id -> PromptVersion`.
//!
//! Production wiring (`server.rs::build_router`, when `CLICKHOUSE_URL` is set):
//!   - In-memory routing + version registry: REAL (this file)
//!   - ClickHouse `promotion_decisions` append on promote: REAL via
//!     `ClickHousePersister` wired with `with_persister(...)`. The default
//!     `NoOpPersister` is used only in unit tests and when no ClickHouse
//!     is configured.
//!   - Eval-gate enforcement on promote(): REAL via `ClickHouseEvalGate`
//!     wired with `with_eval_gate(...)` — a promotion is blocked unless
//!     its eval run is recorded `passed` in `eval_runs`. The default
//!     `PermissiveGate` is used only in unit tests / dev with no DB.
//!
//! Performance budgets:
//! - Routing pointer read (cached):        <1ms p99
//! - Routing pointer read (cache miss):    <50ms p99 (ClickHouse)
//! - Promotion gate latency (eval suite):  <30s p99 (driven by eval runner)

#![allow(dead_code, clippy::needless_pass_by_value)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow, bail};
use arc_swap::ArcSwap;
use clickhouse::Client as ClickhouseClient;
use uuid::Uuid;

use tracelane_shared::TenantId;

use crate::auto_rollback::{PromptMetrics, RollbackDecision, RollbackEngine, RollbackMode};

/// Deployment environment for a routed prompt version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Env {
    Dev,
    Staging,
    Production,
    Canary,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Dev => "dev",
            Env::Staging => "staging",
            Env::Production => "production",
            Env::Canary => "canary",
        }
    }
}

/// Resolved prompt version returned by the router.
#[derive(Debug, Clone)]
pub struct PromptVersion {
    pub prompt_version_id: Uuid,
    pub prompt_id: Uuid,
    pub version_number: u32,
    pub content: String,
    pub model_pin: Option<String>,
    pub sha256: [u8; 32],
}

/// Outcome of a `promote()` call.
#[derive(Debug, Clone)]
pub struct PromotionDecision {
    pub promotion_id: Uuid,
    /// The prompt this decision is about (ADR-054). Carried so the persister
    /// writes the REAL identity into `promotion_decisions` — dropping the old
    /// `prompt_id = to_version_id` proxy that made routing unreconstructable.
    pub prompt_id: Uuid,
    pub prompt_name: String,
    pub from_version_id: Option<Uuid>,
    pub to_version_id: Uuid,
    pub from_env: Env,
    pub to_env: Env,
    pub eval_run_id: Option<Uuid>,
    pub decision: DecisionKind,
    pub notes: String,
    /// WHO made this decision — the authenticated actor (`Claims.sub`, or
    /// `apikey:<id>`), `"system:auto-rollback"` for an engine flip, `None` only
    /// where no caller exists (unit tests).
    ///
    /// This exists because `promotion_decisions.decided_by_user_id` was written
    /// as a hardcoded `None` on EVERY row while `prompt_routes.rs`'s own doc
    /// comment claimed the actor was captured "so an override promotion records
    /// WHO bypassed the eval gate in the tamper-evident decision". It was
    /// captured — into the `notes` PROSE — and the structured, queryable column
    /// stayed NULL. Prod bore that out: 5 promotion rows, every one
    /// `decided_by_user_id = NULL`, one of them with the actor visible only
    /// inside a sentence. A comment naming a control is not a control.
    pub decided_by: Option<String>,
}

/// Fixed UUIDv5 namespace for deriving a stable `prompt_id` from
/// `(tenant_id, prompt_name)` (ADR-054). Deterministic → no `prompts` table and
/// no reverse lookup. Renaming a prompt yields a new id (named trade-off).
const PROMPT_ID_NAMESPACE: Uuid = Uuid::from_u128(0x7c0a_54ad_1e55_4b0e_9a11_7001_1ac0_de54);

/// Stable content-free identity for a prompt within a tenant.
#[must_use]
pub fn prompt_id_for(tenant_id: &TenantId, name: &str) -> Uuid {
    Uuid::new_v5(
        &PROMPT_ID_NAMESPACE,
        format!("{tenant_id}:{name}").as_bytes(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionKind {
    Promoted,
    BlockedByEval,
    BlockedByPolicy,
    ManualOverride,
}

/// Status of an eval run as recorded in `eval_runs.status`. Mirrors the
/// ClickHouse Enum8 in `infra/dev/clickhouse/migrations/03_prompt_promotion.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalRunStatus {
    Running,
    Passed,
    Failed,
    Errored,
}

/// Eval gate hook — looks up an eval run's status by id, scoped to the
/// tenant (every ClickHouse read is tenant-isolated per CLAUDE.md).
/// Production impl (`ClickHouseEvalGate`) queries `eval_runs`; tests pass
/// a static map. Async because the production impl issues a network read —
/// this is the control-plane promote path, not the gateway hot path, so
/// `async_trait` is acceptable here (cf. `PromotionPersister`).
#[async_trait::async_trait]
pub trait EvalGate: Send + Sync {
    async fn status(&self, tenant_id: &TenantId, eval_run_id: Uuid) -> Option<EvalRunStatus>;
}

/// In-process eval gate backed by a static map. Useful for tests and for
/// the gateway's startup-config eval registry. Production swaps in a
/// ClickHouse-backed implementation.
pub struct StaticEvalGate {
    pub statuses: HashMap<Uuid, EvalRunStatus>,
}

#[async_trait::async_trait]
impl EvalGate for StaticEvalGate {
    async fn status(&self, _tenant_id: &TenantId, eval_run_id: Uuid) -> Option<EvalRunStatus> {
        self.statuses.get(&eval_run_id).copied()
    }
}

type RoutingKey = (TenantId, String, Env);

/// Persistence hook for promotion-decisions audit trail.
///
/// Production swaps in `ClickHousePersister`; tests use the default
/// `NoOpPersister` so unit tests don't need a running ClickHouse.
#[async_trait::async_trait]
pub trait PromotionPersister: Send + Sync {
    async fn persist(&self, tenant_id: &TenantId, decision: &PromotionDecision) -> Result<()>;
}

/// Default persister — drops decisions on the floor. Useful for unit
/// tests; production sets `ClickHousePersister`.
pub struct NoOpPersister;

#[async_trait::async_trait]
impl PromotionPersister for NoOpPersister {
    async fn persist(&self, _tenant_id: &TenantId, _decision: &PromotionDecision) -> Result<()> {
        Ok(())
    }
}

/// ClickHouse-backed persister. INSERTs into `tracelane.promotion_decisions`
/// per `infra/dev/clickhouse/migrations/03_prompt_promotion.sql`.
///
/// Async path is non-blocking — `clickhouse::Client.insert(...)` batches
/// internally; failures bubble up so the caller can decide whether to
/// fail the promote() call (default: yes — audit trail is load-bearing).
pub struct ClickHousePersister {
    client: ClickhouseClient,
}

impl ClickHousePersister {
    pub fn new(client: ClickhouseClient) -> Self {
        Self { client }
    }
}

#[derive(Debug, serde::Serialize, clickhouse::Row)]
struct PromotionDecisionRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    promotion_id: ::uuid::Uuid,
    /// The REAL prompt identity (ADR-054). Was previously proxied from
    /// `to_version_id`; now carried on `PromotionDecision` so the startup
    /// reconstruction can rebuild routing by `(tenant, prompt_name, env)`.
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    prompt_name: String,
    #[serde(with = "clickhouse::serde::uuid::option")]
    from_version_id: Option<::uuid::Uuid>,
    #[serde(with = "clickhouse::serde::uuid")]
    to_version_id: ::uuid::Uuid,
    from_env: String,
    to_env: String,
    #[serde(with = "clickhouse::serde::uuid::option")]
    eval_run_id: Option<::uuid::Uuid>,
    decision: String,
    /// Milliseconds since Unix epoch (DateTime64(3) raw ticks).
    decided_at: i64,
    decided_by_user_id: Option<String>,
    notes: String,
}

#[async_trait::async_trait]
impl PromotionPersister for ClickHousePersister {
    async fn persist(&self, tenant_id: &TenantId, decision: &PromotionDecision) -> Result<()> {
        let row = PromotionDecisionRow {
            tenant_id: tenant_id.to_string(),
            promotion_id: decision.promotion_id,
            prompt_id: decision.prompt_id,
            prompt_name: decision.prompt_name.clone(),
            from_version_id: decision.from_version_id,
            to_version_id: decision.to_version_id,
            from_env: decision.from_env.as_str().to_string(),
            to_env: decision.to_env.as_str().to_string(),
            eval_run_id: decision.eval_run_id,
            decision: match decision.decision {
                DecisionKind::Promoted => "promoted".into(),
                DecisionKind::BlockedByEval => "blocked_by_eval".into(),
                DecisionKind::BlockedByPolicy => "blocked_by_policy".into(),
                DecisionKind::ManualOverride => "manual_override".into(),
            },
            // DateTime64(3) = milliseconds. clickhouse-rs maps a plain i64 to the
            // column's raw ticks, so this MUST be millis (was timestamp_micros() —
            // a 1000× overshoot into year ~48000; ADR-054 fix, never verified
            // on-node because promote never ran in prod).
            decided_at: crate::clickhouse_query::datetime64_millis_now(),
            decided_by_user_id: decision.decided_by.clone(),
            notes: decision.notes.clone(),
        };
        let mut insert = self
            .client
            .insert("promotion_decisions")
            .context("clickhouse promotion_decisions insert init")?;
        insert
            .write(&row)
            .await
            .context("clickhouse promotion_decisions insert write")?;
        insert
            .end()
            .await
            .context("clickhouse promotion_decisions insert end")?;
        Ok(())
    }
}

// ── Durable version store (ADR-054) ──────────────────────────────────────────
// The registry (`versions` + `routing`) is in-memory + wait-free on the hot read
// path; this trait is the durable backing that makes authoring survive a restart.
// Control plane (off the hot path) → `async_trait` is fine (cf. PromotionPersister).

/// A prompt + its activity, for the `/v1/prompts` list.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PromptSummary {
    pub name: String,
    pub prompt_id: Uuid,
    pub versions: u32,
    pub latest_version: u32,
    /// Active `version_number` per env (e.g. staging=3, production=2).
    pub active: Vec<PromptEnvActive>,
    /// Last authored version, ms since epoch.
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PromptEnvActive {
    pub env: String,
    pub version_number: u32,
}

/// A routing pointer reconstructed from `promotion_decisions` at startup.
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    pub tenant_id: TenantId,
    pub prompt_name: String,
    pub env: Env,
    pub version_id: Uuid,
}

/// Durable store for authored prompt versions + the list/reconstruction reads.
#[async_trait::async_trait]
pub trait VersionStore: Send + Sync {
    /// Persist a newly-authored version. `template_variables` + `created_by` are
    /// metadata beyond the lean in-memory [`PromptVersion`].
    async fn insert(
        &self,
        tenant_id: &TenantId,
        name: &str,
        v: &PromptVersion,
        template_variables: &[String],
        created_by: &str,
    ) -> Result<()>;
    /// The next version number for a prompt (`max(existing) + 1`, or 1 if none).
    async fn next_version_number(&self, tenant_id: &TenantId, prompt_id: Uuid) -> Result<u32>;
    /// Every stored version (all tenants) — loaded into the registry at startup.
    async fn load_versions(&self) -> Result<Vec<(TenantId, PromptVersion)>>;
    /// The auto-rollback "previous production" map, reconstructed from
    /// `promotion_decisions` at startup: for each `(tenant, prompt_name)`, the
    /// version that the CURRENT production version displaced.
    ///
    /// Defaults to empty so the in-memory and test stores need no change —
    /// they have no durable history to reconstruct from.
    async fn load_prev_production(&self) -> Result<Vec<(TenantId, String, Uuid)>> {
        Ok(Vec::new())
    }

    /// The active routing pointers (latest promotion per (tenant, name, env)),
    /// reconstructed from `promotion_decisions` at startup.
    async fn load_routing(&self) -> Result<Vec<RoutingEntry>>;
    /// The tenant's prompts + activity, for the dashboard list.
    async fn list(&self, tenant_id: &TenantId) -> Result<Vec<PromptSummary>>;
    /// Soft-delete ("archive") a prompt: write an `archived=1` marker to
    /// `prompts` so `list`, `load_versions`, and `load_routing` exclude it
    /// thereafter. Idempotent — re-marking an already-archived prompt is inert.
    async fn archive(
        &self,
        tenant_id: &TenantId,
        name: &str,
        prompt_id: Uuid,
        archived_by: &str,
    ) -> Result<()>;
    /// Un-archive (re-activate) a prompt: write an `archived=0` marker so
    /// re-creating a previously-deleted prompt survives a restart. The exclusion
    /// subqueries read `prompts FINAL`, so the LATEST marker wins (create's
    /// `archived=0` overrides a prior delete's `archived=1`).
    async fn unarchive(
        &self,
        tenant_id: &TenantId,
        name: &str,
        prompt_id: Uuid,
        activated_by: &str,
    ) -> Result<()>;
}

/// Default store — no durability. Unit tests + no-ClickHouse dev.
pub struct NoOpVersionStore;

#[async_trait::async_trait]
impl VersionStore for NoOpVersionStore {
    async fn insert(
        &self,
        _t: &TenantId,
        _n: &str,
        _v: &PromptVersion,
        _tv: &[String],
        _cb: &str,
    ) -> Result<()> {
        Ok(())
    }
    async fn next_version_number(&self, _t: &TenantId, _p: Uuid) -> Result<u32> {
        Ok(1)
    }
    async fn load_versions(&self) -> Result<Vec<(TenantId, PromptVersion)>> {
        Ok(Vec::new())
    }
    async fn load_routing(&self) -> Result<Vec<RoutingEntry>> {
        Ok(Vec::new())
    }
    async fn list(&self, _t: &TenantId) -> Result<Vec<PromptSummary>> {
        Ok(Vec::new())
    }
    async fn archive(&self, _t: &TenantId, _n: &str, _p: Uuid, _by: &str) -> Result<()> {
        Ok(())
    }
    async fn unarchive(&self, _t: &TenantId, _n: &str, _p: Uuid, _by: &str) -> Result<()> {
        Ok(())
    }
}

/// ClickHouse-backed version store (`prompt_versions` + routing reconstruction
/// from `promotion_decisions`). Serialization is proven by the on-node E2E
/// (ADR-054 §Test) — mock-based unit tests exercise the router logic, not this.
pub struct ClickHouseVersionStore {
    client: ClickhouseClient,
}

impl ClickHouseVersionStore {
    pub fn new(client: ClickhouseClient) -> Self {
        Self { client }
    }
}

/// INSERT row for `prompt_versions`. Field order MUST match the table's physical
/// column order (migration 03 + 07 `prompt_name AFTER prompt_id`) — clickhouse-rs
/// RowBinary insert is positional.
#[derive(Debug, serde::Serialize, clickhouse::Row)]
struct PromptVersionInsertRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_version_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    prompt_name: String,
    #[serde(with = "clickhouse::serde::uuid::option")]
    parent_version_id: Option<::uuid::Uuid>,
    version_number: u32,
    content: String,
    template_variables: Vec<String>,
    model_pin: Option<String>,
    /// DateTime64(3) = milliseconds since epoch (raw ticks; see the persister).
    created_at: i64,
    created_by_user_id: String,
    /// FixedString(64) = 64 hex chars.
    sha256: FixedHex64,
}

/// A 64-byte value serialized as a ClickHouse `FixedString(64)` — exactly 64
/// bytes with no length prefix (which a plain `String` would add, and which
/// serde has no `[u8; 64]: Serialize` impl to produce).
pub(crate) struct FixedHex64(pub(crate) [u8; 64]);

impl FixedHex64 {
    /// Build from a 64-char ASCII hex digest. Returns `None` on any other length,
    /// because a short or long value here does not error at the wire — it
    /// DESYNCHRONISES the RowBinary stream and the server reports a byte count
    /// mismatch on some LATER row, which is how this cost an on-node debug once.
    pub(crate) fn from_hex_str(hex: &str) -> Option<Self> {
        let b = hex.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(b);
        Some(Self(out))
    }
}

impl serde::Serialize for FixedHex64 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        // clickhouse-rs writes a FixedString(N) as exactly N raw bytes with NO
        // length prefix. `serialize_bytes` emits String-format (varint len +
        // bytes) → wire mismatch. A fixed tuple of N `u8`s serializes as N raw
        // bytes, which matches FixedString(N) exactly (ADR-054, on-node E2E fix).
        use serde::ser::SerializeTuple as _;
        let mut t = s.serialize_tuple(self.0.len())?;
        for b in &self.0 {
            t.serialize_element(b)?;
        }
        t.end()
    }
}

impl<'de> serde::Deserialize<'de> for FixedHex64 {
    /// THE READ SIDE OF THE SAME WIRE CONTRACT, and its absence was a live prod
    /// defect (**B-274**).
    ///
    /// B-273 fixed the WRITE side and stopped there. Every reader of a
    /// `FixedString(64)` column kept declaring a plain `String`, which makes
    /// clickhouse-rs consume a varint length prefix that a FixedString never
    /// emits — so it reads a length out of the DIGEST'S OWN FIRST BYTES and then
    /// runs off the end of the block. The client reports
    /// *"not enough data, probably a row type mismatches a database schema"*,
    /// which names the row and not the column, on a query that is perfectly
    /// valid SQL.
    ///
    /// `deserialize_tuple(64, …)` is the mirror of the `serialize_tuple` above:
    /// exactly 64 raw bytes, no prefix, in both directions. Putting both halves
    /// on the newtype is the point — a SQL-side `toString()` cast would work too,
    /// but it would have to be remembered at every one of the read sites, and
    /// "remembered at every site" is precisely how the read half was missed.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'d> serde::de::Visitor<'d> for V {
            type Value = FixedHex64;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("64 raw bytes (ClickHouse FixedString(64))")
            }
            fn visit_seq<A: serde::de::SeqAccess<'d>>(
                self,
                mut seq: A,
            ) -> std::result::Result<FixedHex64, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(FixedHex64(out))
            }
        }
        d.deserialize_tuple(64, V)
    }
}

impl FixedHex64 {
    /// The 64 bytes as text. They are ASCII hex by construction —
    /// [`FixedHex64::from_hex_str`] is the only way to build one — so this is
    /// lossless for every value this type can hold.
    pub(crate) fn to_hex_string(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl std::fmt::Debug for FixedHex64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FixedHex64(<64 bytes>)")
    }
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct VersionLoadRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_version_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    version_number: u32,
    content: String,
    /// `ifNull(model_pin, '')` in the SELECT → non-null; '' means "no pin".
    model_pin: String,
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct RoutingLoadRow {
    tenant_id: String,
    prompt_name: String,
    to_env: String,
    #[serde(with = "clickhouse::serde::uuid")]
    to_version_id: ::uuid::Uuid,
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct PrevProductionRow {
    tenant_id: String,
    prompt_name: String,
    /// Non-nullable on the wire: the query maps a SQL NULL to the nil UUID so
    /// argMax can range over every production promotion. Nil means "the newest
    /// production promotion displaced nothing", i.e. no rollback target.
    #[serde(with = "clickhouse::serde::uuid")]
    prev_version_id: ::uuid::Uuid,
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct SummaryRow {
    prompt_name: String,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    versions: u32,
    latest_version: u32,
    updated_at_ms: i64,
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct ActiveRow {
    prompt_name: String,
    to_env: String,
    version_number: u32,
}

/// INSERT row for `prompts` — the soft-delete archive marker. Field order
/// MUST match the table's physical column order (migration 03). `prompts` is
/// `ReplacingMergeTree(created_at)` keyed by `(tenant_id, prompt_id)`, so a marker
/// with a fresh timestamp wins even though authoring never wrote a base row here.
#[derive(Debug, serde::Serialize, clickhouse::Row)]
struct PromptArchiveRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    name: String,
    description: String,
    /// DateTime64(3) = milliseconds since epoch (raw ticks; see the persister).
    created_at: i64,
    created_by_user_id: String,
    archived: u8,
}

/// A single `prompt_id` from the archived-prompts read (soft-deleted rows the
/// list + startup reconstruction exclude).
#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct ArchivedRow {
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
}

/// Parse an `Env` from its stored string; unknown → None (skipped, never mis-routed).
fn env_from_str(s: &str) -> Option<Env> {
    match s {
        "dev" => Some(Env::Dev),
        "staging" => Some(Env::Staging),
        "production" => Some(Env::Production),
        "canary" => Some(Env::Canary),
        _ => None,
    }
}

/// Parse a stored tenant UUID string into a trusted internal [`TenantId`]. The
/// value was written from a validated claim at create time, so this is a trusted
/// internal-UUID source (same class as `from_jwt_claim`), never a request body.
fn tenant_from_stored(s: &str) -> Result<TenantId> {
    Ok(TenantId::from_jwt_claim(
        Uuid::parse_str(s).context("stored tenant_id not a UUID")?,
    ))
}

#[async_trait::async_trait]
impl VersionStore for ClickHouseVersionStore {
    async fn insert(
        &self,
        tenant_id: &TenantId,
        name: &str,
        v: &PromptVersion,
        template_variables: &[String],
        created_by: &str,
    ) -> Result<()> {
        let mut sha256 = [0u8; 64];
        hex::encode_to_slice(v.sha256, &mut sha256).context("sha256 hex encode")?;
        let row = PromptVersionInsertRow {
            tenant_id: tenant_id.to_string(),
            prompt_version_id: v.prompt_version_id,
            prompt_id: v.prompt_id,
            prompt_name: name.to_string(),
            parent_version_id: None,
            version_number: v.version_number,
            content: v.content.clone(),
            template_variables: template_variables.to_vec(),
            model_pin: v.model_pin.clone(),
            created_at: chrono::Utc::now().timestamp_millis(),
            created_by_user_id: created_by.to_string(),
            sha256: FixedHex64(sha256),
        };
        let mut insert = self
            .client
            .insert("prompt_versions")
            .context("prompt_versions insert init")?;
        insert
            .write(&row)
            .await
            .context("prompt_versions insert write")?;
        insert.end().await.context("prompt_versions insert end")?;
        Ok(())
    }

    async fn next_version_number(&self, tenant_id: &TenantId, prompt_id: Uuid) -> Result<u32> {
        let current: u32 = self
            .client
            .query(
                "SELECT toUInt32(ifNull(max(version_number), 0)) \
                 FROM prompt_versions WHERE tenant_id = ? AND prompt_id = ?",
            )
            .bind(tenant_id.to_string())
            .bind(prompt_id)
            .fetch_one::<u32>()
            .await
            .context("prompt_versions max(version_number)")?;
        Ok(current + 1)
    }

    async fn load_versions(&self) -> Result<Vec<(TenantId, PromptVersion)>> {
        let rows = self
            .client
            .query(
                "SELECT tenant_id, prompt_version_id, prompt_id, version_number, content, \
                 ifNull(model_pin, '') FROM prompt_versions \
                 WHERE prompt_id NOT IN (SELECT prompt_id FROM prompts FINAL WHERE archived = 1)",
            )
            .fetch_all::<VersionLoadRow>()
            .await
            .context("prompt_versions load")?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let tenant = tenant_from_stored(&r.tenant_id)?;
            // sha256 recomputed from content (content-addressable) so the load
            // never round-trips the FixedString(64) column.
            let version = PromptVersion {
                prompt_version_id: r.prompt_version_id,
                prompt_id: r.prompt_id,
                version_number: r.version_number,
                sha256: sha256_of(&r.content),
                content: r.content,
                model_pin: if r.model_pin.is_empty() {
                    None
                } else {
                    Some(r.model_pin)
                },
            };
            out.push((tenant, version));
        }
        Ok(out)
    }

    async fn load_prev_production(&self) -> Result<Vec<(TenantId, String, Uuid)>> {
        // `from_version_id` of the MOST RECENT production promotion is, by
        // definition, the version the current production version displaced —
        // which is exactly what `record_prev_production` stores at promote time.
        //
        // `ifNull(..., nil)` rather than a `from_version_id IS NOT NULL` filter:
        // filtering first would make argMax pick an OLDER promotion's displaced
        // version whenever the newest one had none (a first-ever promotion),
        // which is the one case that must yield NO entry. Mapping NULL to the
        // nil UUID keeps argMax over the full set and lets Rust drop it.
        let rows = self
            .client
            .query(
                "SELECT tenant_id, prompt_name, \
                 argMax(ifNull(from_version_id, toUUID('00000000-0000-0000-0000-000000000000')), \
                        decided_at) AS prev_version_id \
                 FROM promotion_decisions \
                 WHERE prompt_name != '' AND to_env = 'production' \
                 AND decision IN ('promoted', 'manual_override') \
                 AND prompt_id NOT IN (SELECT prompt_id FROM prompts FINAL WHERE archived = 1) \
                 GROUP BY tenant_id, prompt_name",
            )
            .fetch_all::<PrevProductionRow>()
            .await
            .context("promotion_decisions prev_production reconstruction")?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            if r.prev_version_id.is_nil() {
                continue; // first-ever production promotion — nothing displaced
            }
            out.push((
                tenant_from_stored(&r.tenant_id)?,
                r.prompt_name,
                r.prev_version_id,
            ));
        }
        Ok(out)
    }

    async fn load_routing(&self) -> Result<Vec<RoutingEntry>> {
        // Latest active promotion per (tenant, prompt_name, to_env). argMax picks
        // the most-recent decided_at; only landed decisions (promoted / override)
        // set routing. Empty prompt_name (pre-migration-07 test rows) is skipped.
        let rows = self
            .client
            .query(
                "SELECT tenant_id, prompt_name, to_env, \
                 argMax(to_version_id, decided_at) AS to_version_id \
                 FROM promotion_decisions \
                 WHERE prompt_name != '' AND decision IN ('promoted', 'manual_override') \
                 AND prompt_id NOT IN (SELECT prompt_id FROM prompts FINAL WHERE archived = 1) \
                 GROUP BY tenant_id, prompt_name, to_env",
            )
            .fetch_all::<RoutingLoadRow>()
            .await
            .context("promotion_decisions routing reconstruction")?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let Some(env) = env_from_str(&r.to_env) else {
                continue;
            };
            out.push(RoutingEntry {
                tenant_id: tenant_from_stored(&r.tenant_id)?,
                prompt_name: r.prompt_name,
                env,
                version_id: r.to_version_id,
            });
        }
        Ok(out)
    }

    async fn list(&self, tenant_id: &TenantId) -> Result<Vec<PromptSummary>> {
        // One prompt row (counts + latest + updated), plus the active version per
        // env — two tenant-scoped reads, joined in Rust.
        let summaries = self
            .client
            .query(
                "SELECT prompt_name, any(prompt_id) AS prompt_id, \
                 toUInt32(uniqExact(version_number)) AS versions, \
                 toUInt32(max(version_number)) AS latest_version, \
                 toInt64(toUnixTimestamp64Milli(max(created_at))) AS updated_at_ms \
                 FROM prompt_versions WHERE tenant_id = ? \
                 GROUP BY prompt_name ORDER BY updated_at_ms DESC",
            )
            .bind(tenant_id.to_string())
            .fetch_all::<SummaryRow>()
            .await
            .context("prompt_versions list")?;

        let active = self
            .client
            .query(
                "SELECT prompt_name, to_env, \
                 argMax(pv.version_number, pd.decided_at) AS version_number \
                 FROM promotion_decisions AS pd \
                 INNER JOIN prompt_versions AS pv ON pd.to_version_id = pv.prompt_version_id \
                 WHERE pd.tenant_id = ? AND pd.prompt_name != '' \
                 AND pd.decision IN ('promoted', 'manual_override') \
                 GROUP BY prompt_name, to_env",
            )
            .bind(tenant_id.to_string())
            .fetch_all::<ActiveRow>()
            .await
            .context("prompt_versions active-per-env")?;

        // Soft-deleted (archived) prompts are excluded from the list.
        let archived: std::collections::HashSet<Uuid> = self
            .client
            .query(
                "SELECT DISTINCT prompt_id FROM prompts FINAL WHERE tenant_id = ? AND archived = 1",
            )
            .bind(tenant_id.to_string())
            .fetch_all::<ArchivedRow>()
            .await
            .context("prompts archived set")?
            .into_iter()
            .map(|r| r.prompt_id)
            .collect();

        let mut by_name: std::collections::HashMap<String, Vec<PromptEnvActive>> =
            std::collections::HashMap::new();
        for a in active {
            by_name
                .entry(a.prompt_name)
                .or_default()
                .push(PromptEnvActive {
                    env: a.to_env,
                    version_number: a.version_number,
                });
        }
        Ok(summaries
            .into_iter()
            .filter(|s| !archived.contains(&s.prompt_id))
            .map(|s| PromptSummary {
                active: by_name.remove(&s.prompt_name).unwrap_or_default(),
                name: s.prompt_name,
                prompt_id: s.prompt_id,
                versions: s.versions,
                latest_version: s.latest_version,
                updated_at_ms: s.updated_at_ms,
            })
            .collect())
    }

    async fn archive(
        &self,
        tenant_id: &TenantId,
        name: &str,
        prompt_id: Uuid,
        archived_by: &str,
    ) -> Result<()> {
        let row = PromptArchiveRow {
            tenant_id: tenant_id.to_string(),
            prompt_id,
            name: name.to_string(),
            description: String::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            created_by_user_id: archived_by.to_string(),
            archived: 1,
        };
        let mut insert = self
            .client
            .insert("prompts")
            .context("prompts archive insert init")?;
        insert
            .write(&row)
            .await
            .context("prompts archive insert write")?;
        insert.end().await.context("prompts archive insert end")?;
        Ok(())
    }

    async fn unarchive(
        &self,
        tenant_id: &TenantId,
        name: &str,
        prompt_id: Uuid,
        activated_by: &str,
    ) -> Result<()> {
        let row = PromptArchiveRow {
            tenant_id: tenant_id.to_string(),
            prompt_id,
            name: name.to_string(),
            description: String::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            created_by_user_id: activated_by.to_string(),
            archived: 0,
        };
        let mut insert = self
            .client
            .insert("prompts")
            .context("prompts unarchive insert init")?;
        insert
            .write(&row)
            .await
            .context("prompts unarchive insert write")?;
        insert.end().await.context("prompts unarchive insert end")?;
        Ok(())
    }
}

/// SHA-256 of a prompt's content, as raw bytes (content-addressable identity).
#[must_use]
pub fn sha256_of(content: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    h.finalize().into()
}

/// In-memory routing pointer cache + version registry.
///
/// Production wiring loads initial routing state from
/// ClickHouse `promotion_decisions` (latest-per-key) at startup, and
/// `prompt_versions` for the version registry.
pub struct PromptRouter {
    /// `(tenant_id, prompt_name, env) -> active prompt_version_id`.
    routing: ArcSwap<HashMap<RoutingKey, Uuid>>,
    /// `prompt_version_id -> PromptVersion`.
    /// Registered versions, keyed by **(tenant, version id)**.
    ///
    /// THE TENANT IS PART OF THE KEY, and it is the whole isolation property.
    /// It used to be keyed by `Uuid` alone while `load_from_clickhouse`
    /// discarded the tenant it had already read, so one process-global map held
    /// every tenant's versions and `route()` resolved any id for anybody. A
    /// promotion with a foreign `to_version_id` therefore served another
    /// tenant's prompt CONTENT — reproduced by executing it, not by reading it.
    /// `ADR-054:29` claims the registry is "tenant-scoped by construction (the
    /// key carries tenant_id)"; the key did not, and per `CLAUDE.md` §17 the
    /// code won and the ADR was the defect. Now it does.
    versions: ArcSwap<HashMap<(TenantId, Uuid), PromptVersion>>,
    /// Eval-gate hook. Defaults to a permissive gate (every eval id reports
    /// Passed). Tests + production override via `with_eval_gate(...)`.
    eval_gate: Arc<dyn EvalGate>,
    /// If true (default), `promote()` requires a passing eval_run_id unless
    /// the caller explicitly invokes `promote_with_override(...)`.
    require_eval_gate: bool,
    /// Audit-trail persister. Defaults to `NoOpPersister`; production
    /// swaps in `ClickHousePersister` via `with_persister(...)`.
    persister: Arc<dyn PromotionPersister>,
    /// Audit-trail reader for the GET history endpoint. Defaults to
    /// `NoOpHistoryReader` (returns empty); production swaps in
    /// `ClickHouseHistoryReader` via `with_history_reader(...)`.
    history_reader: Arc<dyn crate::prompt_history::HistoryReader>,
    /// EWMA drift engine for auto-rollback. Fed via
    /// `observe_and_maybe_rollback(...)`; on objective (Auto) drift the
    /// router flips the production pointer back to `prev_production`.
    /// Defaults to a NoOp-persister engine; production attaches a
    /// `ClickHouseRollbackPersister`-backed engine via `with_rollback_engine`.
    rollback_engine: Arc<RollbackEngine>,
    /// `(tenant_id, prompt_name) -> the version displaced from production by
    /// the most recent production promote`. This is the target an
    /// objective-drift auto-rollback flips back to. Wait-free reads.
    prev_production: ArcSwap<HashMap<(TenantId, String), Uuid>>,
    /// Durable version store (ADR-054). Defaults to `NoOpVersionStore`; production
    /// attaches `ClickHouseVersionStore` via `with_version_store(...)`.
    version_store: Arc<dyn VersionStore>,
}

/// Outcome of an `observe_and_maybe_rollback` call: the engine's drift
/// decision, plus the version the router actually flipped to (Some only
/// when an objective/Auto drift fired AND a previous production version
/// was on record).
#[derive(Debug, Clone)]
pub struct RollbackOutcome {
    pub decision: RollbackDecision,
    pub rolled_back_to: Option<Uuid>,
    /// The `PromotionDecision` from the internal flip, present ONLY when an
    /// auto-rollback actually moved the production pointer. The HTTP layer
    /// chains it as a tamper-evident `eval.verdict` (wedge item 3) so an
    /// automated production change is recorded exactly like a manual one.
    pub auto_rollback_decision: Option<PromotionDecision>,
}

impl PromptRouter {
    /// Construct an empty router with a permissive eval gate (every eval
    /// reports Passed). Use `with_eval_gate(...)` to plug in a real gate.
    pub fn new() -> Self {
        Self {
            routing: ArcSwap::from_pointee(HashMap::new()),
            versions: ArcSwap::from_pointee(HashMap::new()),
            eval_gate: Arc::new(PermissiveGate),
            require_eval_gate: true,
            persister: Arc::new(NoOpPersister),
            history_reader: Arc::new(crate::prompt_history::NoOpHistoryReader),
            rollback_engine: Arc::new(RollbackEngine::new()),
            prev_production: ArcSwap::from_pointee(HashMap::new()),
            version_store: Arc::new(NoOpVersionStore),
        }
    }

    /// Plug in a durable version store. Production: `ClickHouseVersionStore`.
    #[must_use]
    pub fn with_version_store(mut self, store: Arc<dyn VersionStore>) -> Self {
        self.version_store = store;
        self
    }

    /// Attach an auto-rollback engine (production:
    /// `RollbackEngine::new().with_persister(ClickHouseRollbackPersister...)`).
    pub fn with_rollback_engine(mut self, engine: Arc<RollbackEngine>) -> Self {
        self.rollback_engine = engine;
        self
    }

    /// Plug in a persister for the promotion-decisions audit trail.
    /// Production: `ClickHousePersister::new(clickhouse_client)`.
    pub fn with_persister(mut self, persister: Arc<dyn PromotionPersister>) -> Self {
        self.persister = persister;
        self
    }

    /// Plug in a history reader. Production:
    /// `ClickHouseHistoryReader::new(clickhouse_client)`.
    pub fn with_history_reader(
        mut self,
        reader: Arc<dyn crate::prompt_history::HistoryReader>,
    ) -> Self {
        self.history_reader = reader;
        self
    }

    /// Read the configured history reader. Used by the GET history route.
    pub fn history_reader(&self) -> Arc<dyn crate::prompt_history::HistoryReader> {
        Arc::clone(&self.history_reader)
    }

    /// Plug in a custom eval gate. Production: ClickHouse-backed.
    pub fn with_eval_gate(mut self, gate: Arc<dyn EvalGate>) -> Self {
        self.eval_gate = gate;
        self
    }

    /// Disable eval-gate enforcement on `promote()`. Use only for dev/test —
    /// in production `promote()` requires a passing eval_run_id and uses
    /// `promote_with_override()` for explicit human bypass.
    pub fn without_eval_gate(mut self) -> Self {
        self.require_eval_gate = false;
        self
    }

    /// Add a prompt version to the in-memory registry. Production loads
    /// this from ClickHouse `prompt_versions` at startup; this method is
    /// the explicit hook for tests and dev tooling.
    pub fn register_version(&self, tenant_id: &TenantId, v: PromptVersion) {
        let key = (tenant_id.clone(), v.prompt_version_id);
        self.versions.rcu(|map| {
            let mut next = (**map).clone();
            next.insert(key.clone(), v.clone());
            next
        });
    }

    /// The version, if `tenant_id` owns it.
    ///
    /// The read half of [`Self::tenant_owns_version`], for callers that need the
    /// version's own content and model pin rather than just a yes/no — the eval
    /// engine runs the version's content as the system instruction, so it has to
    /// resolve the object it was authorized against, not a second lookup that
    /// could disagree.
    #[must_use]
    pub fn version_for_tenant(
        &self,
        tenant_id: &TenantId,
        version_id: Uuid,
    ) -> Option<PromptVersion> {
        self.versions
            .load()
            .get(&(tenant_id.clone(), version_id))
            .cloned()
    }

    /// Does `version_id` belong to `tenant_id`?
    ///
    /// The object-level authorization check `promote` / `promote_with_override`
    /// were missing. **Fails CLOSED** (`CLAUDE.md` §10): a cold or
    /// failed-to-load registry answers `false`, so a promotion is refused
    /// rather than allowed against a version whose ownership cannot be
    /// established. Refusing to promote is recoverable; serving another
    /// tenant's prompt is not.
    fn tenant_owns_version(&self, tenant_id: &TenantId, version_id: Uuid) -> bool {
        self.versions
            .load()
            .contains_key(&(tenant_id.clone(), version_id))
    }

    /// Author a new prompt version (ADR-054): compute the identity, persist it
    /// durably, register it in-memory, and land it in `staging` so it is
    /// immediately resolvable AND the routing survives a restart.
    ///
    /// Builder-allowed (authoring is read-adjacent); promotion to production is
    /// the separate Team+ action.
    ///
    /// # Errors
    /// Fail-closed: if the durable insert or the staging landing cannot be
    /// recorded, returns `Err` — we never leave an in-memory version that isn't
    /// durable.
    #[tracing::instrument(skip(self, content), fields(tenant_id = %tenant_id))]
    pub async fn create_version(
        &self,
        tenant_id: &TenantId,
        name: &str,
        content: String,
        model_pin: Option<String>,
        template_variables: Vec<String>,
        created_by: &str,
    ) -> Result<PromptVersion> {
        let prompt_id = prompt_id_for(tenant_id, name);
        let version_number = self
            .version_store
            .next_version_number(tenant_id, prompt_id)
            .await?;
        let version = PromptVersion {
            prompt_version_id: Uuid::new_v4(),
            prompt_id,
            version_number,
            sha256: sha256_of(&content),
            content,
            model_pin,
        };
        // Durable FIRST — a failed insert must not leave a dangling in-memory
        // version.
        self.version_store
            .insert(tenant_id, name, &version, &template_variables, created_by)
            .await?;
        // Re-creating a previously-deleted prompt must un-archive it (write an
        // archived=0 marker, newest-wins via `prompts FINAL`) — else the stale
        // delete marker would exclude the new version from load_versions /
        // load_routing after a restart (silent data loss).
        self.version_store
            .unarchive(tenant_id, name, prompt_id, created_by)
            .await?;
        self.register_version(tenant_id, version.clone());
        // Land in staging (routing + a promotion_decisions row → survives restart).
        // The initial landing has no eval run, so it uses the override path.
        self.promote_with_override(
            tenant_id.clone(),
            name,
            Env::Dev,
            Env::Staging,
            version.prompt_version_id,
            "initial version created",
            Some(created_by),
        )
        .await?;
        Ok(version)
    }

    /// Soft-delete ("archive") a prompt: durably mark it archived, then
    /// drop its in-memory routing pointers + version registry entries so the
    /// gateway stops serving it immediately. Survives a restart because `list`,
    /// `load_versions`, and `load_routing` all exclude archived prompt_ids.
    ///
    /// Builder-allowed — the inverse of authoring (`create_version`), NOT the
    /// Team+ promotion gate: a user removes a prompt they authored. Idempotent:
    /// deleting an already-archived prompt re-marks it (the marker is inert).
    ///
    /// # Errors
    /// Fail-closed: if the durable archive marker cannot be written, returns
    /// `Err` and NOTHING is dropped in-memory — never a silent partial delete.
    #[tracing::instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub async fn delete_prompt(
        &self,
        tenant_id: &TenantId,
        name: &str,
        deleted_by: &str,
    ) -> Result<()> {
        let prompt_id = prompt_id_for(tenant_id, name);
        // Durable FIRST — mirror create_version's ordering; never drop an
        // in-memory prompt whose archived state isn't durable.
        self.version_store
            .archive(tenant_id, name, prompt_id, deleted_by)
            .await?;
        // Drop every registered version for this prompt.
        self.versions.rcu(|map| {
            let mut next = (**map).clone();
            next.retain(|_vid, v| v.prompt_id != prompt_id);
            next
        });
        // Drop every routing pointer for (tenant, name) across all envs, plus the
        // auto-rollback "previous production" record so a stale entry can't fire.
        self.routing.rcu(|map| {
            let mut next = (**map).clone();
            next.retain(|k, _| k.0 != *tenant_id || k.1.as_str() != name);
            next
        });
        self.prev_production.rcu(|map| {
            let mut next = (**map).clone();
            next.retain(|k, _| k.0 != *tenant_id || k.1.as_str() != name);
            next
        });
        Ok(())
    }

    /// Load the durable registry + routing at startup (ADR-054). Fail-open: on a
    /// load error the router starts empty — a cold store must never crash the
    /// gateway (cf. the guardrail registry loader).
    pub async fn load_from_clickhouse(&self) {
        match self.version_store.load_versions().await {
            Ok(versions) => {
                let map: HashMap<(TenantId, Uuid), PromptVersion> = versions
                    .into_iter()
                    .map(|(t, v)| ((t, v.prompt_version_id), v))
                    .collect();
                let n = map.len();
                self.versions.store(Arc::new(map));
                tracing::info!(versions = n, "prompt registry loaded from ClickHouse");
            }
            Err(err) => {
                tracing::warn!(
                    error = format!("{err:#}"),
                    "prompt version load failed — registry starts empty"
                );
            }
        }
        // `prev_production` is the auto-rollback FLIP TARGET, and it used to be
        // in-memory only: written by `record_prev_production` during a promote,
        // cleared on delete, and never rebuilt. Every restart emptied it, so
        // after any deploy the drift check fired, found no target, logged a
        // warning and did nothing. Production promotions are rare (prod has had
        // five, all in July), so in practice auto-rollback was dead in
        // production from the first deploy after each one — a feature that
        // reported healthy and could not act. Reconstructing it here is what
        // makes it survive a restart, exactly as routing already did.
        match self.version_store.load_prev_production().await {
            Ok(entries) => {
                let mut map: HashMap<(TenantId, String), Uuid> = HashMap::new();
                for (tenant_id, prompt_name, prev) in entries {
                    map.insert((tenant_id, prompt_name), prev);
                }
                let n = map.len();
                self.prev_production.store(Arc::new(map));
                tracing::info!(
                    targets = n,
                    "auto-rollback previous-production targets reconstructed from ClickHouse"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = format!("{err:#}"),
                    "prev_production reconstruction failed — auto-rollback has no flip target \
                     until the next production promotion"
                );
            }
        }
        match self.version_store.load_routing().await {
            Ok(entries) => {
                let mut map: HashMap<RoutingKey, Uuid> = HashMap::new();
                for e in entries {
                    map.insert((e.tenant_id, e.prompt_name, e.env), e.version_id);
                }
                let n = map.len();
                self.routing.store(Arc::new(map));
                tracing::info!(pointers = n, "prompt routing reconstructed from ClickHouse");
            }
            Err(err) => {
                tracing::warn!(
                    error = format!("{err:#}"),
                    "prompt routing load failed — routing starts empty"
                );
            }
        }
    }

    /// The tenant's prompts + activity for the dashboard list.
    ///
    /// # Errors
    /// Propagates a store read error.
    pub async fn list_prompts(&self, tenant_id: &TenantId) -> Result<Vec<PromptSummary>> {
        self.version_store.list(tenant_id).await
    }

    /// Resolve the active prompt version for `(tenant_id, prompt_name, env)`.
    ///
    /// Reads the in-memory pointer in <1ms wait-free. If the pointer or the
    /// underlying version isn't registered, returns `Err`. Production adds a
    /// ClickHouse fallback for cold cache; the in-memory hot-path is unchanged.
    #[tracing::instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub async fn route(
        &self,
        tenant_id: TenantId,
        prompt_name: &str,
        env: Env,
    ) -> Result<PromptVersion> {
        let key: RoutingKey = (tenant_id.clone(), prompt_name.to_string(), env);
        let routing = self.routing.load();
        let version_id = routing
            .get(&key)
            .copied()
            .ok_or_else(|| anyhow!("no routing pointer for {prompt_name:?} in {env:?}"))?;
        let versions = self.versions.load();
        versions
            .get(&(tenant_id, version_id))
            .cloned()
            .ok_or_else(|| {
                anyhow!("version {version_id} registered as active but missing from registry")
            })
    }

    /// Atomically swap the routing pointer for `(tenant, prompt_name, to_env)`
    /// and append a `promotion_decisions` row.
    ///
    /// Eval-gate enforcement (assertion 1):
    ///   - `eval_run_id = Some(id)` and gate reports `Passed` → promoted
    ///   - `eval_run_id = Some(id)` and gate reports `Failed`/`Errored`/`Running`
    ///     → `BlockedByEval`
    ///   - `eval_run_id = None` and `require_eval_gate=true` → `BlockedByPolicy`
    ///   - `eval_run_id = None` and `require_eval_gate=false` → promoted
    ///     (dev mode only)
    ///
    /// `promote_with_override()` exists as a separate entry point for the
    /// explicit human bypass case; it always records `ManualOverride`.
    // 8 arguments: the 7 that describe the promotion, plus the ACTOR, which is
    // an audit fact and not a convenience — see `PromotionDecision::decided_by`.
    // Bundling them into a request struct would be tidier and is deliberately
    // not done here: it would rewrite ~20 call sites in the middle of a security
    // fix. Same `#[allow]` the adjacent hot-path fns already carry
    // (`server.rs:1205`, `:3277`, `:4356`, `:4799`).
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub async fn promote(
        &self,
        tenant_id: TenantId,
        prompt_name: &str,
        from_env: Env,
        to_env: Env,
        to_version_id: Uuid,
        eval_run_id: Option<Uuid>,
        actor: Option<&str>,
    ) -> Result<PromotionDecision> {
        // OBJECT-LEVEL AUTHORIZATION. `to_version_id` arrives from the request
        // body; without this a tenant could point its own routing pointer at
        // ANY version id it happened to know and then read that version's
        // content back through `route()`. Reproduced by execution before this
        // check existed: tenant A promoted tenant B's version id under a name
        // of A's choosing and `GET /v1/prompts/<name>?env=production` returned
        // B's prompt text. Fails CLOSED — see `tenant_owns_version`.
        if !self.tenant_owns_version(&tenant_id, to_version_id) {
            bail!("prompt version {to_version_id} is not a registered version for this tenant");
        }
        // Eval-gate check.
        let decision_kind = match (eval_run_id, self.require_eval_gate) {
            (Some(id), _) => match self.eval_gate.status(&tenant_id, id).await {
                Some(EvalRunStatus::Passed) => DecisionKind::Promoted,
                Some(EvalRunStatus::Failed | EvalRunStatus::Errored) => DecisionKind::BlockedByEval,
                Some(EvalRunStatus::Running) => DecisionKind::BlockedByEval,
                None => DecisionKind::BlockedByEval,
            },
            (None, true) => DecisionKind::BlockedByPolicy,
            (None, false) => DecisionKind::Promoted,
        };

        // Capture the previous routing pointer for from_version_id (audit).
        let key_to: RoutingKey = (tenant_id.clone(), prompt_name.to_string(), to_env);
        let from_version_id = self.routing.load().get(&key_to).copied();

        let notes = match decision_kind {
            DecisionKind::Promoted => format!(
                "promoted {prompt_name} {} -> {} via eval_run {}",
                from_env.as_str(),
                to_env.as_str(),
                eval_run_id
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "none".into()),
            ),
            DecisionKind::BlockedByEval => format!(
                "blocked: eval gate failed for run {}",
                eval_run_id
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "none".into()),
            ),
            DecisionKind::BlockedByPolicy => {
                "blocked: require_eval_gate=true and no eval_run_id provided".into()
            }
            DecisionKind::ManualOverride => "manual override".into(),
        };

        let decision = PromotionDecision {
            promotion_id: Uuid::new_v4(),
            prompt_id: prompt_id_for(&tenant_id, prompt_name),
            prompt_name: prompt_name.to_string(),
            from_version_id,
            to_version_id,
            from_env,
            to_env,
            eval_run_id,
            decision: decision_kind,
            notes,
            decided_by: actor.map(str::to_owned),
        };

        // Atomically swap the routing pointer iff the decision allows it.
        if matches!(
            decision_kind,
            DecisionKind::Promoted | DecisionKind::ManualOverride
        ) {
            self.routing.rcu(|map| {
                let mut next = (**map).clone();
                next.insert(key_to.clone(), to_version_id);
                next
            });
            self.record_prev_production(
                &tenant_id,
                prompt_name,
                to_env,
                from_version_id,
                to_version_id,
            );
        }

        self.persist_promotion(&tenant_id, &decision).await?;

        Ok(decision)
    }

    /// Remember the version displaced from production so an objective-drift
    /// auto-rollback knows where to flip back to. No-op unless `to_env` is
    /// Production and a distinct previous version was displaced.
    fn record_prev_production(
        &self,
        tenant_id: &TenantId,
        prompt_name: &str,
        to_env: Env,
        displaced: Option<Uuid>,
        to_version_id: Uuid,
    ) {
        if to_env != Env::Production {
            return;
        }
        let Some(prev) = displaced else { return };
        if prev == to_version_id {
            return;
        }
        let key = (tenant_id.clone(), prompt_name.to_string());
        self.prev_production.rcu(|map| {
            let mut next = (**map).clone();
            next.insert(key.clone(), prev);
            next
        });
    }

    /// Explicit human-bypass promotion. Records `ManualOverride` in the
    /// audit trail. Always swaps the routing pointer.
    // 8 arguments: the 7 that describe the promotion, plus the ACTOR, which is
    // an audit fact and not a convenience — see `PromotionDecision::decided_by`.
    // Bundling them into a request struct would be tidier and is deliberately
    // not done here: it would rewrite ~20 call sites in the middle of a security
    // fix. Same `#[allow]` the adjacent hot-path fns already carry
    // (`server.rs:1205`, `:3277`, `:4356`, `:4799`).
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub async fn promote_with_override(
        &self,
        tenant_id: TenantId,
        prompt_name: &str,
        from_env: Env,
        to_env: Env,
        to_version_id: Uuid,
        operator_note: &str,
        actor: Option<&str>,
    ) -> Result<PromotionDecision> {
        // OBJECT-LEVEL AUTHORIZATION. `to_version_id` arrives from the request
        // body; without this a tenant could point its own routing pointer at
        // ANY version id it happened to know and then read that version's
        // content back through `route()`. Reproduced by execution before this
        // check existed: tenant A promoted tenant B's version id under a name
        // of A's choosing and `GET /v1/prompts/<name>?env=production` returned
        // B's prompt text. Fails CLOSED — see `tenant_owns_version`.
        if !self.tenant_owns_version(&tenant_id, to_version_id) {
            bail!("prompt version {to_version_id} is not a registered version for this tenant");
        }
        let key_to: RoutingKey = (tenant_id.clone(), prompt_name.to_string(), to_env);
        let from_version_id = self.routing.load().get(&key_to).copied();

        let decision = PromotionDecision {
            promotion_id: Uuid::new_v4(),
            prompt_id: prompt_id_for(&tenant_id, prompt_name),
            prompt_name: prompt_name.to_string(),
            from_version_id,
            to_version_id,
            from_env,
            to_env,
            eval_run_id: None,
            decision: DecisionKind::ManualOverride,
            notes: format!("manual override: {operator_note}"),
            decided_by: actor.map(str::to_owned),
        };

        self.routing.rcu(|map| {
            let mut next = (**map).clone();
            next.insert(key_to.clone(), to_version_id);
            next
        });
        self.record_prev_production(
            &tenant_id,
            prompt_name,
            to_env,
            from_version_id,
            to_version_id,
        );

        self.persist_promotion(&tenant_id, &decision).await?;
        Ok(decision)
    }

    /// Feed one observation into the EWMA engine, refusing versions this tenant
    /// does not own.
    ///
    /// **The ownership check is what bounds this map.** The engine's state is
    /// `HashMap<(TenantId, Uuid), MetricStates>` keyed on a version id that
    /// arrives, on the chat path, straight out of the REQUEST BODY. Without a
    /// check, any caller could mint unlimited distinct UUIDs and grow that map
    /// without bound, and could poison the baseline for a version belonging to a
    /// prompt they never touched. Constraining the key space to versions the
    /// tenant actually registered fixes both: the map is now bounded by the
    /// tenant's real version count.
    async fn feed_engine(
        &self,
        tenant_id: &TenantId,
        prompt_version_id: Uuid,
        metrics: &PromptMetrics,
    ) -> Result<()> {
        if !self.tenant_owns_version(tenant_id, prompt_version_id) {
            bail!("prompt version {prompt_version_id} is not a registered version for this tenant");
        }
        self.rollback_engine
            .observe(tenant_id.clone(), prompt_version_id, metrics)
            .await;
        Ok(())
    }

    /// Observe metrics and COMPUTE a rollback decision, with no authority to act
    /// on it. This is what the chat hot path calls.
    ///
    /// **Why the hot path gets a separate entry point rather than a flag.**
    /// `chat_completions_handler` reads `tracelane_prompt_name`,
    /// `tracelane_prompt_version_id` and `tracelane_prompt_env` out of the chat
    /// REQUEST BODY and fed them straight into `observe_and_maybe_rollback`,
    /// which flips the production routing pointer. That made the chat body a
    /// sixth prompt-WRITE surface with none of the five gates the HTTP write
    /// surfaces carry — no owner role, no Team+ entitlement, no scope. A Viewer
    /// JWT or a `chat`-scoped key could drive the EWMA to near-zero variance
    /// with ~30 identical completions (`COLD_START` is 30) and then flip
    /// production with the 31st.
    ///
    /// Gating that call would have worked; REMOVING THE CAPABILITY is better,
    /// because it cannot be un-gated by a later edit that does not know why the
    /// gate was there. The pointer flip is now reachable only through
    /// `observe_and_maybe_rollback`, whose sole caller is the `/observe` route —
    /// which authenticates, checks the owner role, checks the Team+ entitlement
    /// and now checks the `admin` scope.
    pub async fn observe_only(
        &self,
        tenant_id: TenantId,
        prompt_version_id: Uuid,
        metrics: &PromptMetrics,
    ) -> Result<RollbackOutcome> {
        self.feed_engine(&tenant_id, prompt_version_id, metrics)
            .await?;
        let decision = self
            .rollback_engine
            .check_and_rollback(tenant_id, prompt_version_id, metrics)
            .await?;
        Ok(RollbackOutcome {
            decision,
            rolled_back_to: None,
            auto_rollback_decision: None,
        })
    }

    /// Observe a prompt-version's request metrics and, on objective (Auto)
    /// drift in production, automatically flip the routing pointer back to
    /// the previously-promoted production version.
    ///
    /// This is the consumer that closes the B1 auto-rollback loop (ADR-009
    /// §7.4.3): the `RollbackEngine` decision is acted upon, not merely
    /// computed. Subjective (accuracy/hallucination) drift returns a
    /// `Suggested` decision WITHOUT flipping — the dashboard surfaces it for
    /// human confirmation. If no previous production version is on record
    /// the Auto decision is returned but the flip is skipped (logged).
    ///
    /// # Errors
    /// Propagates persistence errors from the rollback-event audit trail and
    /// any error from the routing-pointer rollback. Fail-closed: a metric
    /// observation that cannot be durably recorded surfaces to the caller.
    #[tracing::instrument(skip(self, metrics), fields(tenant_id = %tenant_id))]
    pub async fn observe_and_maybe_rollback(
        &self,
        tenant_id: TenantId,
        prompt_name: &str,
        env: Env,
        prompt_version_id: Uuid,
        metrics: &PromptMetrics,
    ) -> Result<RollbackOutcome> {
        self.feed_engine(&tenant_id, prompt_version_id, metrics)
            .await?;
        let decision = self
            .rollback_engine
            .check_and_rollback(tenant_id.clone(), prompt_version_id, metrics)
            .await?;

        let mut rolled_back_to = None;
        let mut auto_rollback_decision = None;
        if decision.mode == Some(RollbackMode::Auto) && env == Env::Production {
            let target = self
                .prev_production
                .load()
                .get(&(tenant_id.clone(), prompt_name.to_string()))
                .copied();
            match target {
                Some(prev) => {
                    let flip = self
                        .rollback(
                            tenant_id.clone(),
                            prompt_name,
                            env,
                            prev,
                            &format!(
                                "auto-rollback: {:?} drift {:.2}σ (value {:.4} vs baseline {:.4})",
                                decision.trigger_metric,
                                decision.sigma_drift,
                                decision.trigger_value,
                                decision.ewma_baseline,
                            ),
                            // Matches the actor string the audit chain already
                            // uses for an engine flip (`prompt_routes.rs`
                            // chain_eval_verdict), so the ClickHouse column and
                            // the tamper-evident chain name the same actor.
                            Some("system:auto-rollback"),
                        )
                        .await?;
                    rolled_back_to = Some(prev);
                    auto_rollback_decision = Some(flip);
                    tracing::warn!(
                        %prompt_name, rolled_back_to = %prev,
                        "objective drift — auto-rolled production pointer back"
                    );
                }
                None => {
                    tracing::warn!(
                        %prompt_name,
                        "objective drift fired but no previous production version on record; \
                         no flip performed (this version was the first promoted to production)"
                    );
                }
            }
        }

        Ok(RollbackOutcome {
            decision,
            rolled_back_to,
            auto_rollback_decision,
        })
    }

    /// Roll back to a specific previous version. Records the rollback as a
    /// `ManualOverride` (since it bypasses the eval gate by design).
    #[tracing::instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub async fn rollback(
        &self,
        tenant_id: TenantId,
        prompt_name: &str,
        env: Env,
        to_version_id: Uuid,
        reason: &str,
        actor: Option<&str>,
    ) -> Result<PromotionDecision> {
        self.promote_with_override(
            tenant_id,
            prompt_name,
            env,
            env,
            to_version_id,
            &format!("rollback: {reason}"),
            actor,
        )
        .await
    }

    /// Audit-trail persistence — delegates to the configured persister.
    /// Default `NoOpPersister` drops the decision (unit tests); production
    /// `ClickHousePersister` writes a row to `promotion_decisions`.
    async fn persist_promotion(
        &self,
        tenant_id: &TenantId,
        decision: &PromotionDecision,
    ) -> Result<()> {
        self.persister.persist(tenant_id, decision).await
    }
}

impl Default for PromptRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Eval gate that always reports `Passed`. Used as the default for unit
/// tests and for dev runs with no ClickHouse configured. Production swaps
/// in `ClickHouseEvalGate` via `server.rs` (`with_eval_gate`).
struct PermissiveGate;

#[async_trait::async_trait]
impl EvalGate for PermissiveGate {
    async fn status(&self, _tenant_id: &TenantId, _eval_run_id: Uuid) -> Option<EvalRunStatus> {
        Some(EvalRunStatus::Passed)
    }
}

/// ClickHouse-backed eval gate. Resolves an eval run's status from
/// `tracelane.eval_runs`, tenant-isolated. Wired by `server.rs` whenever
/// `CLICKHOUSE_URL` is set; it replaces the permissive default so a
/// promotion is blocked unless its eval run is recorded `passed`.
///
/// # Errors / fail-closed
/// On a query error or a missing/unknown status this returns `None`,
/// which `promote()` maps to `BlockedByEval` — a promotion never silently
/// proceeds on an unreadable gate (security-relevant gate ⇒ fail closed).
pub struct ClickHouseEvalGate {
    client: ClickhouseClient,
}

impl ClickHouseEvalGate {
    pub fn new(client: ClickhouseClient) -> Self {
        Self { client }
    }
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct EvalStatusRow {
    status: String,
}

#[async_trait::async_trait]
impl EvalGate for ClickHouseEvalGate {
    #[tracing::instrument(skip(self), fields(tenant_id = %tenant_id))]
    async fn status(&self, tenant_id: &TenantId, eval_run_id: Uuid) -> Option<EvalRunStatus> {
        // ADR-031 V1.1 sweep: single-row PK lookup, tenant-scoped and
        // LIMIT-bounded — internally bounded like the prompt-history
        // reads, so per-tier caps are additive. Exempted in
        // `scripts/ci/no-raw-ch-query.sh`; V1.1 routes through TenantQuery.
        let rows = self
            .client
            .query(
                "SELECT status FROM eval_runs \
                 WHERE tenant_id = ? AND eval_run_id = ? \
                 ORDER BY completed_at DESC \
                 LIMIT 1",
            )
            .bind(tenant_id.to_string())
            .bind(eval_run_id)
            .fetch_all::<EvalStatusRow>()
            .await;

        let status = match rows {
            Ok(mut rows) => rows.pop()?.status,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    %eval_run_id,
                    "eval gate query failed; failing closed (promotion blocked)"
                );
                return None;
            }
        };

        match status.as_str() {
            "running" => Some(EvalRunStatus::Running),
            "passed" => Some(EvalRunStatus::Passed),
            "failed" => Some(EvalRunStatus::Failed),
            "errored" => Some(EvalRunStatus::Errored),
            other => {
                tracing::warn!(status = %other, %eval_run_id, "unknown eval_runs.status value");
                None
            }
        }
    }
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn tid(n: u128) -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(n))
    }

    fn pv(prompt_id: Uuid, version_number: u32) -> PromptVersion {
        PromptVersion {
            prompt_version_id: Uuid::from_u128(
                (prompt_id.as_u128()).wrapping_add(version_number as u128),
            ),
            prompt_id,
            version_number,
            content: format!("v{version_number} content"),
            model_pin: Some("claude-sonnet-4-6".into()),
            sha256: [0u8; 32],
        }
    }

    /// In-memory store for the router-logic tests (no ClickHouse). Records
    /// inserts, hands out increasing version numbers, and replays fixtures for
    /// the startup-load test. The ClickHouse serialization is proven separately
    /// by the on-node E2E (ADR-054 §Test), never by this mock.
    #[derive(Default)]
    struct MockVersionStore {
        inserted: std::sync::Mutex<Vec<(String, u32)>>,
        next: std::sync::atomic::AtomicU32,
        versions: Vec<(TenantId, PromptVersion)>,
        routing: Vec<RoutingEntry>,
        /// (name, prompt_id) archive markers recorded via `archive`.
        archived: std::sync::Mutex<Vec<(String, Uuid)>>,
        /// (name, prompt_id) un-archive markers recorded via `unarchive`.
        unarchived: std::sync::Mutex<Vec<(String, Uuid)>>,
        /// When set, `archive` returns Err — exercises delete's fail-closed path.
        archive_fails: std::sync::atomic::AtomicBool,
        /// Durable auto-rollback flip targets, as reconstructed at boot.
        prev_production: Vec<(TenantId, String, Uuid)>,
    }

    #[async_trait::async_trait]
    impl VersionStore for MockVersionStore {
        async fn insert(
            &self,
            _t: &TenantId,
            name: &str,
            v: &PromptVersion,
            _tv: &[String],
            _cb: &str,
        ) -> Result<()> {
            self.inserted
                .lock()
                .unwrap()
                .push((name.to_string(), v.version_number));
            Ok(())
        }
        async fn next_version_number(&self, _t: &TenantId, _p: Uuid) -> Result<u32> {
            Ok(self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
        }
        async fn load_versions(&self) -> Result<Vec<(TenantId, PromptVersion)>> {
            Ok(self.versions.clone())
        }
        async fn load_prev_production(&self) -> Result<Vec<(TenantId, String, Uuid)>> {
            Ok(self.prev_production.clone())
        }
        async fn load_routing(&self) -> Result<Vec<RoutingEntry>> {
            Ok(self.routing.clone())
        }
        async fn list(&self, _t: &TenantId) -> Result<Vec<PromptSummary>> {
            Ok(Vec::new())
        }
        async fn archive(
            &self,
            _t: &TenantId,
            name: &str,
            prompt_id: Uuid,
            _by: &str,
        ) -> Result<()> {
            if self.archive_fails.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("archive failed (test)");
            }
            self.archived
                .lock()
                .unwrap()
                .push((name.to_string(), prompt_id));
            Ok(())
        }
        async fn unarchive(
            &self,
            _t: &TenantId,
            name: &str,
            prompt_id: Uuid,
            _by: &str,
        ) -> Result<()> {
            self.unarchived
                .lock()
                .unwrap()
                .push((name.to_string(), prompt_id));
            Ok(())
        }
    }

    #[tokio::test]
    async fn create_version_unarchives_for_restart_survival() {
        // Re-creating a prompt (esp. one previously deleted) must write an
        // archived=0 marker so `prompts FINAL` stops excluding it on the next
        // startup load — otherwise the re-created version silently vanishes on
        // restart (the create-after-delete data-loss the audit caught).
        let store = Arc::new(MockVersionStore::default());
        let r = PromptRouter::new().with_version_store(store.clone());
        let t = tid(30);
        let v = r
            .create_version(&t, "greet", "hi".into(), None, vec![], "u")
            .await
            .unwrap();
        assert_eq!(
            store.unarchived.lock().unwrap().as_slice(),
            &[("greet".to_string(), v.prompt_id)],
            "create writes an archived=0 marker so a re-created prompt survives a restart \
             — AND so every `prompt_versions` row has a parent `prompts` row (R85). \
             `demoprompt2` on prod is the one violation: created 2026-07-08 02:46:09, \
             hours BEFORE `c8786383` added this call the same day, so it is routable and \
             listed by GET /v1/prompts (which reads the registry) while having NO `prompts` \
             row at all. Every prompt created after that fix is consistent. This assertion \
             is what stops the invariant regressing; removing the `unarchive` call would \
             strand every future version the same way."
        );
    }

    #[tokio::test]
    async fn route_returns_err_when_no_pointer() {
        let r = PromptRouter::new();
        let err = r.route(tid(1), "missing", Env::Production).await;
        assert!(err.is_err());
    }

    #[test]
    fn prompt_id_is_stable_per_tenant_and_name() {
        assert_eq!(prompt_id_for(&tid(1), "x"), prompt_id_for(&tid(1), "x"));
        assert_ne!(prompt_id_for(&tid(1), "x"), prompt_id_for(&tid(1), "y"));
        // Same name, different tenant → different id (no cross-tenant collision).
        assert_ne!(prompt_id_for(&tid(1), "x"), prompt_id_for(&tid(2), "x"));
    }

    #[test]
    fn sha256_of_matches_known_vector() {
        // SHA-256("") — the canonical empty-string digest.
        assert_eq!(
            hex::encode(sha256_of("")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn create_version_registers_and_lands_in_staging() {
        let store = Arc::new(MockVersionStore::default());
        let r = PromptRouter::new().with_version_store(store.clone());
        let t = tid(7);
        let v = r
            .create_version(&t, "greeting", "hello".into(), None, vec![], "user_1")
            .await
            .unwrap();
        assert_eq!(v.version_number, 1);
        assert_eq!(v.prompt_id, prompt_id_for(&t, "greeting"));
        assert_eq!(v.sha256, sha256_of("hello"));
        // Registered AND routed to staging → immediately resolvable.
        let resolved = r.route(t.clone(), "greeting", Env::Staging).await.unwrap();
        assert_eq!(resolved.prompt_version_id, v.prompt_version_id);
        assert_eq!(resolved.content, "hello");
        // Durable insert happened (before the register — fail-closed ordering).
        assert_eq!(
            store.inserted.lock().unwrap().as_slice(),
            &[("greeting".to_string(), 1)]
        );
    }

    #[tokio::test]
    async fn create_version_increments_version_number() {
        let r = PromptRouter::new().with_version_store(Arc::new(MockVersionStore::default()));
        let t = tid(8);
        let v1 = r
            .create_version(&t, "p", "a".into(), None, vec![], "u")
            .await
            .unwrap();
        let v2 = r
            .create_version(&t, "p", "b".into(), None, vec![], "u")
            .await
            .unwrap();
        assert_eq!(v1.version_number, 1);
        assert_eq!(v2.version_number, 2);
    }

    #[tokio::test]
    async fn create_version_is_tenant_isolated() {
        let r = PromptRouter::new().with_version_store(Arc::new(MockVersionStore::default()));
        let (a, b) = (tid(10), tid(11));
        r.create_version(&a, "shared", "x".into(), None, vec![], "u")
            .await
            .unwrap();
        // Tenant A resolves its staging version; tenant B has no pointer.
        assert!(r.route(a.clone(), "shared", Env::Staging).await.is_ok());
        assert!(r.route(b.clone(), "shared", Env::Staging).await.is_err());
    }

    #[tokio::test]
    async fn load_from_clickhouse_rebuilds_registry_and_routing() {
        let t = tid(9);
        let version = PromptVersion {
            prompt_version_id: Uuid::from_u128(0xABC),
            prompt_id: prompt_id_for(&t, "welcome"),
            version_number: 3,
            content: "loaded".into(),
            model_pin: None,
            sha256: sha256_of("loaded"),
        };
        let store = MockVersionStore {
            versions: vec![(t.clone(), version.clone())],
            routing: vec![RoutingEntry {
                tenant_id: t.clone(),
                prompt_name: "welcome".into(),
                env: Env::Production,
                version_id: version.prompt_version_id,
            }],
            ..Default::default()
        };
        let r = PromptRouter::new().with_version_store(Arc::new(store));
        r.load_from_clickhouse().await;
        let resolved = r
            .route(t.clone(), "welcome", Env::Production)
            .await
            .unwrap();
        assert_eq!(resolved.prompt_version_id, version.prompt_version_id);
        assert_eq!(resolved.content, "loaded");
    }

    /// AUTO-ROLLBACK MUST SURVIVE A RESTART.
    ///
    /// `prev_production` — the flip TARGET — was in-memory only: written by
    /// `record_prev_production` during a promote, cleared on delete, and never
    /// rebuilt at boot. Every restart emptied it, so after a deploy the drift
    /// check fired, found no target, logged a warning and did nothing. Prod has
    /// had five production promotions ever, all in July, so in practice the
    /// feature was dead there from the first deploy after each one — reporting
    /// healthy and unable to act.
    ///
    /// This simulates a cold process: the store holds the durable history, the
    /// router is fresh, and drift must still flip.
    #[tokio::test]
    async fn auto_rollback_flip_target_survives_a_restart() {
        async fn drive_drift_after_boot(
            prev_production: Vec<(TenantId, String, Uuid)>,
        ) -> Option<Uuid> {
            let t = tid(0x5E7);
            let prompt_id = Uuid::from_u128(0x5E7);
            let va = pv(prompt_id, 1);
            let vb = pv(prompt_id, 2);
            let store = MockVersionStore {
                versions: vec![(t.clone(), va.clone()), (t.clone(), vb.clone())],
                routing: vec![RoutingEntry {
                    tenant_id: t.clone(),
                    prompt_name: "p".into(),
                    env: Env::Production,
                    version_id: vb.prompt_version_id,
                }],
                prev_production,
                ..Default::default()
            };
            // A FRESH router — nothing was promoted in this process.
            let r = PromptRouter::new()
                .without_eval_gate()
                .with_version_store(Arc::new(store));
            r.load_from_clickhouse().await;

            for i in 0..100 {
                r.observe_and_maybe_rollback(
                    t.clone(),
                    "p",
                    Env::Production,
                    vb.prompt_version_id,
                    &PromptMetrics {
                        cost_usd: 0.001 + ((i % 5) as f64) * 1e-6,
                        latency_ms: 250.0,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            }
            r.observe_and_maybe_rollback(
                t,
                "p",
                Env::Production,
                vb.prompt_version_id,
                &PromptMetrics {
                    cost_usd: 0.05,
                    latency_ms: 250.0,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .rolled_back_to
        }

        let t = tid(0x5E7);
        let va = pv(Uuid::from_u128(0x5E7), 1);

        // Reconstructed at boot → the flip finds its target.
        assert_eq!(
            drive_drift_after_boot(vec![(t, "p".into(), va.prompt_version_id)]).await,
            Some(va.prompt_version_id),
            "a reconstructed prev_production must let auto-rollback flip after a restart"
        );

        // DISCRIMINATION: the same drift, with nothing reconstructed, is the
        // pre-fix behaviour — the decision fires and the flip cannot happen.
        // Without this half the assertion above could pass for any reason.
        assert_eq!(
            drive_drift_after_boot(vec![]).await,
            None,
            "with no reconstructed target the flip cannot happen — this is exactly \
             what every deploy used to produce"
        );
    }

    #[tokio::test]
    async fn delete_prompt_archives_and_drops_from_memory() {
        let store = Arc::new(MockVersionStore::default());
        let r = PromptRouter::new().with_version_store(store.clone());
        let t = tid(20);
        let v = r
            .create_version(&t, "greet", "hi".into(), None, vec![], "u")
            .await
            .unwrap();
        // Present + resolvable before delete.
        assert!(r.route(t.clone(), "greet", Env::Staging).await.is_ok());
        // Delete → durable archive marker recorded + in-memory routing dropped.
        r.delete_prompt(&t, "greet", "u").await.unwrap();
        assert!(
            r.route(t.clone(), "greet", Env::Staging).await.is_err(),
            "routing pointer dropped → gateway no longer serves it"
        );
        assert_eq!(
            store.archived.lock().unwrap().as_slice(),
            &[("greet".to_string(), v.prompt_id)],
            "archive marker written durably for the prompt_id"
        );
    }

    #[tokio::test]
    async fn delete_prompt_is_tenant_isolated() {
        let r = PromptRouter::new().with_version_store(Arc::new(MockVersionStore::default()));
        let (a, b) = (tid(21), tid(22));
        r.create_version(&a, "shared", "x".into(), None, vec![], "u")
            .await
            .unwrap();
        r.create_version(&b, "shared", "y".into(), None, vec![], "u")
            .await
            .unwrap();
        // Deleting tenant A's "shared" leaves tenant B's identically-named prompt.
        r.delete_prompt(&a, "shared", "u").await.unwrap();
        assert!(
            r.route(a.clone(), "shared", Env::Staging).await.is_err(),
            "A's pointer gone"
        );
        assert!(
            r.route(b.clone(), "shared", Env::Staging).await.is_ok(),
            "B's pointer intact — no cross-tenant delete"
        );
    }

    #[tokio::test]
    async fn delete_prompt_fails_closed_when_archive_errors() {
        let store = Arc::new(MockVersionStore::default());
        store
            .archive_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let r = PromptRouter::new().with_version_store(store.clone());
        let t = tid(23);
        r.create_version(&t, "keep", "v".into(), None, vec![], "u")
            .await
            .unwrap();
        // Durable archive fails → delete errors AND nothing is dropped in-memory.
        assert!(r.delete_prompt(&t, "keep", "u").await.is_err());
        assert!(
            r.route(t.clone(), "keep", Env::Staging).await.is_ok(),
            "not dropped when the archive write failed (no silent partial delete)"
        );
        assert!(
            store.archived.lock().unwrap().is_empty(),
            "no marker recorded on failure"
        );
    }

    /// Reproduce the PRODUCTION promote wiring and prove promote-to-prod 409s
    /// when the gate cannot resolve a PASSING run:
    ///   - promote WITH an unresolvable eval_run_id → `BlockedByEval` (HTTP 409)
    ///   - promote WITHOUT an eval_run_id           → `BlockedByPolicy` (HTTP 409)
    /// and neither flips the production pointer.
    ///
    /// **RENAMED 2026-08-19, and the old name was a prediction that turned out
    /// wrong.** It was `…_always_409s_until_eval_runs_is_written`, and both it
    /// and `specs/EVL-05` said it would go RED the day a writer landed. It did
    /// not, and the reason is worth keeping: this test supplies a `StaticEvalGate`
    /// with NO rows, so the gate returns `None` whether or not a writer exists
    /// anywhere in the repo. What actually opens the gate is a run recorded
    /// `passed` — the writer is necessary but not sufficient. `EVL-05` landed the
    /// writer and this test still passes, correctly.
    ///
    /// So it is not a canary for the feature's absence; it is a permanent
    /// assertion that **the gate fails CLOSED when it cannot resolve a passing
    /// run**, which is the property worth keeping forever.
    /// `promote_succeeds_with_passing_eval` is its positive twin.
    #[tokio::test]
    async fn promote_in_production_config_409s_without_a_passing_eval_run() {
        let store = Arc::new(MockVersionStore::default());
        let router = PromptRouter::new()
            .with_version_store(store.clone())
            .with_eval_gate(Arc::new(StaticEvalGate {
                statuses: std::collections::HashMap::new(), // prod eval_runs is empty
            }));
        let t = tid(88);
        let v = router
            .create_version(&t, "checkout-prompt", "v1".into(), None, vec![], "u")
            .await
            .unwrap();

        // (a) promote WITH an eval_run_id → gate reads empty eval_runs → BlockedByEval.
        let with_id = router
            .promote(
                t.clone(),
                "checkout-prompt",
                Env::Staging,
                Env::Production,
                v.prompt_version_id,
                Some(Uuid::new_v4()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(with_id.decision, DecisionKind::BlockedByEval);

        // (b) promote WITHOUT an eval_run_id → BlockedByPolicy.
        let no_id = router
            .promote(
                t.clone(),
                "checkout-prompt",
                Env::Staging,
                Env::Production,
                v.prompt_version_id,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(no_id.decision, DecisionKind::BlockedByPolicy);

        // Observable end-state: neither 409 flipped the production pointer.
        assert!(
            router
                .route(t.clone(), "checkout-prompt", Env::Production)
                .await
                .is_err(),
            "no user promote reached production — promote-to-prod is a dead end"
        );

        // The ONLY working prod-pointer flip today is the internal override.
        router
            .promote_with_override(
                t.clone(),
                "checkout-prompt",
                Env::Staging,
                Env::Production,
                v.prompt_version_id,
                "manual override",
                None,
            )
            .await
            .unwrap();
        assert!(
            router
                .route(t.clone(), "checkout-prompt", Env::Production)
                .await
                .is_ok(),
            "override is the only path that reaches production today"
        );
    }

    /// REAL-ClickHouse round-trip of the full create_version WRITE path — the
    /// serialization the mock tests can't cover (FixedString(64) sha256,
    /// DateTime64 created_at, UUID columns, Array/Nullable). Author → the version
    /// + its staging-landing land in CH → a FRESH router reloads + resolves them.
    /// This is the on-node E2E's local twin (ADR-054 §Test).
    ///
    /// Run: start a ClickHouse, apply `prompt_versions` + `promotion_decisions`,
    /// then `CLICKHOUSE_TEST_URL=http://localhost:18123 cargo test -p gateway \
    /// --bin gateway create_version_round_trips_on_real_ch -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "needs a local ClickHouse with the prompt schema (CLICKHOUSE_TEST_URL)"]
    async fn create_version_round_trips_on_real_ch() {
        let url = std::env::var("CLICKHOUSE_TEST_URL")
            .unwrap_or_else(|_| "http://localhost:18123".into());
        let mk_store = || {
            Arc::new(ClickHouseVersionStore::new(
                crate::clickhouse_query::ch_client(url.clone()),
            ))
        };
        let persister = Arc::new(ClickHousePersister::new(
            crate::clickhouse_query::ch_client(url.clone()),
        ));
        let router = PromptRouter::new()
            .with_version_store(mk_store())
            .with_persister(persister);
        let tenant = tid(0x000E_2E10);

        let v = router
            .create_version(
                &tenant,
                "local-e2e",
                "You are good tech leader".into(),
                Some("gpt-4o-mini".into()),
                vec!["user_query".into()],
                "e2e-user",
            )
            .await
            .expect("create_version must WRITE to real CH (FixedString/DateTime64/UUID/Array)");
        assert_eq!(v.version_number, 1);
        assert_eq!(v.sha256, sha256_of("You are good tech leader"));

        // A FRESH router reconstructs it from CH → proves the write AND the
        // read/routing reconstruction end-to-end.
        let fresh = PromptRouter::new().with_version_store(mk_store());
        fresh.load_from_clickhouse().await;
        let resolved = fresh
            .route(tenant, "local-e2e", Env::Staging)
            .await
            .expect("must resolve after reload from real CH");
        assert_eq!(resolved.prompt_version_id, v.prompt_version_id);
        assert_eq!(resolved.content, "You are good tech leader");
        println!(
            "✓ create_version real-CH round-trip OK: v{}",
            v.version_number
        );
    }

    // -- FT-10 chaos (ADR-038 §23.4) -------------------------------------
    //
    // Un-skips `evals/fault-tolerance/FT-10-concurrent-promotion-rollback`'s
    // integration case. The release-vs-detection invariant has two halves:
    //   1. concurrent promotions on one prompt must serialize through the
    //      arc-swap routing pointer with no torn/missing state, and
    //   2. an objective-drift auto-rollback must target the SPECIFIC version
    //      it displaced (attribution-keyed), not "the last change" nor the
    //      first-ever production version.
    // Both run fully in-process — no ClickHouse — because the routing and
    // prev-production pointers are in-memory arc-swaps; persistence is a
    // best-effort side channel that does not gate the flip.

    /// FT-10 (a): two near-simultaneous promotions on one prompt serialize
    /// through the arc-swap pointer; both succeed and the final pointer is
    /// exactly one of the two registered versions — never torn or absent.
    #[tokio::test]
    async fn ft10_concurrent_promotions_serialize_without_corruption() {
        let r = Arc::new(PromptRouter::new().without_eval_gate());
        let t = tid(0x10A);
        let prompt_id = Uuid::from_u128(0x10A);
        let va = pv(prompt_id, 1);
        let vb = pv(prompt_id, 2);
        r.register_version(&t, va.clone());
        r.register_version(&t, vb.clone());

        let (r1, r2) = (Arc::clone(&r), Arc::clone(&r));
        let (t1, t2) = (t.clone(), t.clone());
        let (va_id, vb_id) = (va.prompt_version_id, vb.prompt_version_id);
        let (ra, rb) = tokio::join!(
            async move {
                r1.promote(
                    t1,
                    "concurrent",
                    Env::Staging,
                    Env::Production,
                    va_id,
                    None,
                    None,
                )
                .await
            },
            async move {
                r2.promote(
                    t2,
                    "concurrent",
                    Env::Staging,
                    Env::Production,
                    vb_id,
                    None,
                    None,
                )
                .await
            },
        );
        // Both promotions completed without panicking or erroring.
        assert_eq!(ra.unwrap().decision, DecisionKind::Promoted);
        assert_eq!(rb.unwrap().decision, DecisionKind::Promoted);

        // The final routing pointer resolves to a registered version — proving
        // the rcu serialised the two writers rather than tearing the map.
        let routed = r
            .route(t.clone(), "concurrent", Env::Production)
            .await
            .expect("pointer resolves to a registered version");
        assert!(
            routed.prompt_version_id == va.prompt_version_id
                || routed.prompt_version_id == vb.prompt_version_id,
            "final pointer must be one of the two concurrent promotions",
        );
    }

    /// FT-10 (b): rollback is attribution-keyed. With vA→vB→vC promoted to
    /// production in sequence, an objective cost spike on vC must roll back to
    /// vB (the version vC displaced), NOT vA (the first-ever production).
    /// THE HOT PATH MUST NOT BE ABLE TO MOVE PRODUCTION.
    ///
    /// `chat_completions_handler` reads `tracelane_prompt_version_id` out of the
    /// chat REQUEST BODY and feeds the rollback engine. While that feed went
    /// through `observe_and_maybe_rollback`, a Viewer JWT or a `chat`-scoped key
    /// could warm the EWMA with ~30 identical completions and then flip the
    /// production pointer with a spike on the 31st — a sixth prompt-WRITE
    /// surface carrying none of the five gates the HTTP write routes carry.
    ///
    /// This drives the EXACT drift that `observe_and_maybe_rollback` acts on,
    /// through `observe_only`, and asserts production does not move.
    #[tokio::test]
    async fn observe_only_computes_drift_but_cannot_flip_production() {
        let r = PromptRouter::new().without_eval_gate();
        let t = tid(0x0B5);
        let prompt_id = Uuid::from_u128(0x0B5);
        let va = pv(prompt_id, 1);
        let vb = pv(prompt_id, 2);
        r.register_version(&t, va.clone());
        r.register_version(&t, vb.clone());
        let name = "victim";

        // vA → production, then vB displaces it, so `prev_production` holds vA
        // and a flip has somewhere to go. Without this the test would pass for
        // the wrong reason.
        for v in [&va, &vb] {
            r.promote(
                t.clone(),
                name,
                Env::Staging,
                Env::Production,
                v.prompt_version_id,
                None,
                None,
            )
            .await
            .unwrap();
        }

        // Warm the EWMA past COLD_START (30), same recipe as the flip test.
        for i in 0..100 {
            let out = r
                .observe_only(
                    t.clone(),
                    vb.prompt_version_id,
                    &PromptMetrics {
                        cost_usd: 0.001 + ((i % 5) as f64) * 1e-6,
                        latency_ms: 250.0,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert!(out.rolled_back_to.is_none());
        }

        // The spike that DOES fire an Auto decision on the flipping path.
        let out = r
            .observe_only(
                t.clone(),
                vb.prompt_version_id,
                &PromptMetrics {
                    cost_usd: 0.05,
                    latency_ms: 250.0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // The DECISION is still computed — the hot path keeps its signal.
        assert_eq!(
            out.decision.mode,
            Some(RollbackMode::Auto),
            "observe_only must still compute the drift decision"
        );
        // ...but it carries no authority, and production did not move.
        assert!(
            out.rolled_back_to.is_none(),
            "observe_only must never roll back"
        );
        assert!(
            out.auto_rollback_decision.is_none(),
            "observe_only must never produce a promotion decision"
        );
        assert_eq!(
            r.route(t.clone(), name, Env::Production)
                .await
                .unwrap()
                .prompt_version_id,
            vb.prompt_version_id,
            "the production pointer must still be vB — the chat path cannot flip it"
        );

        // DISCRIMINATION. Everything above would also pass if the drift simply
        // were not flip-worthy — a probe that cannot tell the two answers apart
        // proves nothing. Feed the SAME metrics through the flipping entry
        // point and require that it DOES flip, so the assertions above are
        // about authority rather than about the numbers.
        let flipped = r
            .observe_and_maybe_rollback(
                t.clone(),
                name,
                Env::Production,
                vb.prompt_version_id,
                &PromptMetrics {
                    cost_usd: 0.05,
                    latency_ms: 250.0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            flipped.rolled_back_to,
            Some(va.prompt_version_id),
            "the same drift MUST flip through the gated path — otherwise the \
             no-flip assertions above are vacuous"
        );
        assert_eq!(
            r.route(t, name, Env::Production)
                .await
                .unwrap()
                .prompt_version_id,
            va.prompt_version_id,
        );
    }

    /// The EWMA map is keyed on a version id that arrives from the request body.
    /// Feeding an id the tenant does not own is refused, which is what bounds
    /// the map and stops one prompt's metrics poisoning another's baseline.
    #[tokio::test]
    async fn observe_only_refuses_a_version_the_tenant_does_not_own() {
        let r = PromptRouter::new().without_eval_gate();
        let owner = tid(0x0B6);
        let stranger = tid(0x0B7);
        let v = pv(Uuid::from_u128(0x0B6), 1);
        r.register_version(&owner, v.clone());

        r.observe_only(
            owner.clone(),
            v.prompt_version_id,
            &PromptMetrics::default(),
        )
        .await
        .expect("the owning tenant may report metrics for its own version");

        assert!(
            r.observe_only(stranger, v.prompt_version_id, &PromptMetrics::default())
                .await
                .is_err(),
            "another tenant must not be able to feed metrics for this version"
        );
        assert!(
            r.observe_only(
                owner,
                Uuid::from_u128(0xDEADBEEF),
                &PromptMetrics::default()
            )
            .await
            .is_err(),
            "an unregistered id must be refused — otherwise the body can grow the map without bound"
        );
    }

    #[tokio::test]
    async fn ft10_attribution_rollback_targets_specific_displaced_version() {
        let r = PromptRouter::new().without_eval_gate();
        let t = tid(0x10B);
        let prompt_id = Uuid::from_u128(0x10B);
        let va = pv(prompt_id, 1);
        let vb = pv(prompt_id, 2);
        let vc = pv(prompt_id, 3);
        for v in [&va, &vb, &vc] {
            r.register_version(&t, (*v).clone());
        }
        let name = "attribution";
        // vA→prod, vB displaces vA, vC displaces vB ⇒ prev_production = vB.
        for v in [&va, &vb, &vc] {
            r.promote(
                t.clone(),
                name,
                Env::Staging,
                Env::Production,
                v.prompt_version_id,
                None,
                None,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            r.route(t.clone(), name, Env::Production)
                .await
                .unwrap()
                .prompt_version_id,
            vc.prompt_version_id,
        );

        // Warm the EWMA drift engine past COLD_START (30) on vC with the
        // codebase's proven-stable cost recipe; no rollback may fire here.
        for i in 0..100 {
            let out = r
                .observe_and_maybe_rollback(
                    t.clone(),
                    name,
                    Env::Production,
                    vc.prompt_version_id,
                    &PromptMetrics {
                        cost_usd: 0.001 + ((i % 5) as f64) * 1e-6,
                        latency_ms: 250.0,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert!(
                out.rolled_back_to.is_none(),
                "stable warm-up must not trigger a rollback",
            );
            assert!(
                out.auto_rollback_decision.is_none(),
                "no flip → nothing to chain",
            );
        }

        // 50× objective cost spike on vC → Auto drift → auto-rollback.
        let out = r
            .observe_and_maybe_rollback(
                t.clone(),
                name,
                Env::Production,
                vc.prompt_version_id,
                &PromptMetrics {
                    cost_usd: 0.05,
                    latency_ms: 250.0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(out.decision.mode, Some(RollbackMode::Auto));
        assert_eq!(
            out.rolled_back_to,
            Some(vb.prompt_version_id),
            "attribution rollback must target the displaced version (vB), not vA",
        );
        assert_eq!(
            r.route(t.clone(), name, Env::Production)
                .await
                .unwrap()
                .prompt_version_id,
            vb.prompt_version_id,
            "production pointer must now serve vB after auto-rollback",
        );
    }

    #[tokio::test]
    async fn promote_blocked_when_no_eval_run() {
        let r = PromptRouter::new();
        let prompt_id = Uuid::from_u128(0xAAAA);
        let v1 = pv(prompt_id, 1);
        r.register_version(&tid(2), v1.clone());

        let decision = r
            .promote(
                tid(2),
                "my-prompt",
                Env::Staging,
                Env::Production,
                v1.prompt_version_id,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(decision.decision, DecisionKind::BlockedByPolicy);
        // Routing pointer NOT updated.
        assert!(r.route(tid(2), "my-prompt", Env::Production).await.is_err());
    }

    #[tokio::test]
    async fn promote_succeeds_with_passing_eval() {
        // Eval gate reports Passed for eval_run id `0xBEEF`.
        let mut statuses = HashMap::new();
        let eval_run = Uuid::from_u128(0xBEEF);
        statuses.insert(eval_run, EvalRunStatus::Passed);
        let gate = Arc::new(StaticEvalGate { statuses });

        let r = PromptRouter::new().with_eval_gate(gate);
        let prompt_id = Uuid::from_u128(0xCAFE);
        let v1 = pv(prompt_id, 1);
        r.register_version(&tid(3), v1.clone());

        let decision = r
            .promote(
                tid(3),
                "support-bot",
                Env::Staging,
                Env::Production,
                v1.prompt_version_id,
                Some(eval_run),
                None,
            )
            .await
            .unwrap();
        assert_eq!(decision.decision, DecisionKind::Promoted);
        // Routing pointer updated.
        let routed = r
            .route(tid(3), "support-bot", Env::Production)
            .await
            .unwrap();
        assert_eq!(routed.prompt_version_id, v1.prompt_version_id);
        assert_eq!(routed.version_number, 1);
    }

    #[tokio::test]
    async fn promote_blocked_when_eval_failed() {
        let mut statuses = HashMap::new();
        let eval_run = Uuid::from_u128(0xDEAD);
        statuses.insert(eval_run, EvalRunStatus::Failed);
        let gate = Arc::new(StaticEvalGate { statuses });

        let r = PromptRouter::new().with_eval_gate(gate);
        let prompt_id = Uuid::from_u128(0xF00D);
        let v1 = pv(prompt_id, 1);
        r.register_version(&tid(4), v1.clone());

        let decision = r
            .promote(
                tid(4),
                "p",
                Env::Staging,
                Env::Production,
                v1.prompt_version_id,
                Some(eval_run),
                None,
            )
            .await
            .unwrap();
        assert_eq!(decision.decision, DecisionKind::BlockedByEval);
    }

    #[tokio::test]
    async fn manual_override_bypasses_eval_gate() {
        let r = PromptRouter::new();
        let prompt_id = Uuid::from_u128(0x1234);
        let v1 = pv(prompt_id, 1);
        r.register_version(&tid(5), v1.clone());

        let decision = r
            .promote_with_override(
                tid(5),
                "incident-prompt",
                Env::Staging,
                Env::Production,
                v1.prompt_version_id,
                "incident response — bypassing eval per runbook IR-042",
                None,
            )
            .await
            .unwrap();
        assert_eq!(decision.decision, DecisionKind::ManualOverride);
        let routed = r
            .route(tid(5), "incident-prompt", Env::Production)
            .await
            .unwrap();
        assert_eq!(routed.prompt_version_id, v1.prompt_version_id);
    }

    /// A capturing persister — the ONLY way to assert what actually reaches
    /// `promotion_decisions`, because `ClickHousePersister` needs a server and
    /// `NoOpPersister` drops the decision on the floor. Every existing promotion
    /// test asserts the RETURNED decision, which is why a persister that wrote a
    /// hardcoded `None` into `decided_by_user_id` survived unnoticed.
    #[derive(Default)]
    struct CapturingPersister {
        seen: std::sync::Mutex<Vec<PromotionDecision>>,
    }

    #[async_trait::async_trait]
    impl PromotionPersister for CapturingPersister {
        async fn persist(&self, _tenant_id: &TenantId, decision: &PromotionDecision) -> Result<()> {
            self.seen.lock().unwrap().push(decision.clone());
            Ok(())
        }
    }

    /// The actor must reach the PERSISTED decision, not just the audit chain.
    ///
    /// Prod held 5 `promotion_decisions` rows, every one with
    /// `decided_by_user_id = NULL`, while one of them carried the actor inside
    /// the `notes` prose — and `prompt_routes.rs`'s doc comment claimed the
    /// actor was captured "so an override promotion records WHO bypassed the
    /// eval gate in the tamper-evident decision". It was captured into a
    /// sentence. This asserts the structured column instead.
    #[tokio::test]
    async fn override_promotion_persists_the_actor_not_just_the_note() {
        let cap = Arc::new(CapturingPersister::default());
        let r = PromptRouter::new().with_persister(cap.clone());
        let prompt_id = Uuid::from_u128(0x51D3);
        let v1 = pv(prompt_id, 1);
        r.register_version(&tid(21), v1.clone());

        r.promote_with_override(
            tid(21),
            "incident-prompt",
            Env::Staging,
            Env::Production,
            v1.prompt_version_id,
            "user override by user_01ABC: incident IR-042",
            Some("user_01ABC"),
        )
        .await
        .unwrap();

        let seen = cap.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the override must persist exactly one row");
        assert_eq!(
            seen[0].decided_by.as_deref(),
            Some("user_01ABC"),
            "decided_by must carry the actor — this is the column that was NULL \
             on every production row"
        );
        assert_eq!(seen[0].decision, DecisionKind::ManualOverride);
    }

    /// The eval-gated path records its actor too — an allowed promotion is as
    /// much an audit fact as a bypass.
    #[tokio::test]
    async fn eval_gated_promotion_persists_the_actor() {
        let mut statuses = HashMap::new();
        let eval_run = Uuid::from_u128(0x5EED);
        statuses.insert(eval_run, EvalRunStatus::Passed);
        let cap = Arc::new(CapturingPersister::default());
        let r = PromptRouter::new()
            .with_persister(cap.clone())
            .with_eval_gate(Arc::new(StaticEvalGate { statuses }));
        let prompt_id = Uuid::from_u128(0x51D4);
        let v1 = pv(prompt_id, 1);
        r.register_version(&tid(22), v1.clone());

        r.promote(
            tid(22),
            "support-bot",
            Env::Staging,
            Env::Production,
            v1.prompt_version_id,
            Some(eval_run),
            Some("user_01XYZ"),
        )
        .await
        .unwrap();

        let seen = cap.seen.lock().unwrap();
        assert_eq!(seen[0].decided_by.as_deref(), Some("user_01XYZ"));
        assert_eq!(seen[0].decision, DecisionKind::Promoted);
    }

    /// An engine-initiated flip is attributed to the engine, with the SAME
    /// string the audit chain uses (`prompt_routes.rs` chain_eval_verdict), so
    /// the ClickHouse column and the tamper-evident chain never disagree about
    /// who moved the pointer.
    #[tokio::test]
    async fn auto_rollback_flip_is_attributed_to_the_engine() {
        let cap = Arc::new(CapturingPersister::default());
        let r = PromptRouter::new().with_persister(cap.clone());
        let prompt_id = Uuid::from_u128(0x51D5);
        let v1 = pv(prompt_id, 1);
        r.register_version(&tid(23), v1.clone());

        r.rollback(
            tid(23),
            "p",
            Env::Production,
            v1.prompt_version_id,
            "auto-rollback: Cost drift 3.10\u{3c3}",
            Some("system:auto-rollback"),
        )
        .await
        .unwrap();

        let seen = cap.seen.lock().unwrap();
        assert_eq!(seen[0].decided_by.as_deref(), Some("system:auto-rollback"));
    }

    #[tokio::test]
    async fn rollback_records_previous_version() {
        let r = PromptRouter::new().without_eval_gate();
        let prompt_id = Uuid::from_u128(0x9999);
        let v1 = pv(prompt_id, 1);
        let v2 = pv(prompt_id, 2);
        r.register_version(&tid(6), v1.clone());
        r.register_version(&tid(6), v2.clone());

        // Promote v1 -> production.
        r.promote(
            tid(6),
            "p",
            Env::Staging,
            Env::Production,
            v1.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();
        // Promote v2 -> production (no eval gate enforced in this test).
        r.promote(
            tid(6),
            "p",
            Env::Staging,
            Env::Production,
            v2.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            r.route(tid(6), "p", Env::Production)
                .await
                .unwrap()
                .version_number,
            2
        );
        // Roll back to v1.
        let rb = r
            .rollback(
                tid(6),
                "p",
                Env::Production,
                v1.prompt_version_id,
                "v2 burned cost budget by 5x",
                None,
            )
            .await
            .unwrap();
        assert_eq!(rb.decision, DecisionKind::ManualOverride);
        assert_eq!(rb.from_version_id, Some(v2.prompt_version_id));
        assert_eq!(rb.to_version_id, v1.prompt_version_id);
        // Routing pointer is back to v1.
        assert_eq!(
            r.route(tid(6), "p", Env::Production)
                .await
                .unwrap()
                .version_number,
            1
        );
    }

    #[tokio::test]
    async fn cross_tenant_routing_is_isolated() {
        let r = PromptRouter::new().without_eval_gate();
        let prompt_id = Uuid::from_u128(0x5555);
        let v_a = pv(prompt_id, 1);
        let v_b = pv(prompt_id, 2);
        // Each version is registered under ITS OWN tenant. The registry is
        // keyed by (tenant, version_id); registering both under one tenant is
        // what the old global map did, and it is what let one tenant resolve
        // the other's version.
        r.register_version(&tid(100), v_a.clone());
        r.register_version(&tid(101), v_b.clone());

        // Tenant A points at v_a; Tenant B points at v_b.
        r.promote(
            tid(100),
            "shared-name",
            Env::Staging,
            Env::Production,
            v_a.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();
        r.promote(
            tid(101),
            "shared-name",
            Env::Staging,
            Env::Production,
            v_b.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();

        let a = r
            .route(tid(100), "shared-name", Env::Production)
            .await
            .unwrap();
        let b = r
            .route(tid(101), "shared-name", Env::Production)
            .await
            .unwrap();
        assert_eq!(a.version_number, 1);
        assert_eq!(b.version_number, 2);

        // THE LEAK ITSELF. Before the registry was tenant-keyed and `promote`
        // checked ownership, tenant A could name tenant B's version id under a
        // prompt name of A's own choosing and then READ B's content back.
        // Reproduced by execution at the time; refused now.
        let leak = r
            .promote(
                tid(100),
                "anything",
                Env::Staging,
                Env::Production,
                v_b.prompt_version_id, // tenant 101's version
                None,
                None,
            )
            .await;
        assert!(
            leak.is_err(),
            "tenant A must not be able to promote tenant B's version id"
        );
        assert!(
            r.route(tid(100), "anything", Env::Production)
                .await
                .is_err(),
            "and no routing pointer may have been created by the refused promote"
        );
    }

    #[tokio::test]
    async fn auto_drift_flips_production_pointer() {
        let r = PromptRouter::new().without_eval_gate();
        let prompt_id = Uuid::from_u128(0x7777);
        let v1 = pv(prompt_id, 1);
        let v2 = pv(prompt_id, 2);
        r.register_version(&tid(70), v1.clone());
        r.register_version(&tid(70), v2.clone());
        let t = tid(70);

        // Promote v1 then v2 to production → prev_production = v1.
        r.promote(
            t.clone(),
            "p",
            Env::Staging,
            Env::Production,
            v1.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();
        r.promote(
            t.clone(),
            "p",
            Env::Staging,
            Env::Production,
            v2.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            r.route(t.clone(), "p", Env::Production)
                .await
                .unwrap()
                .version_number,
            2
        );

        // Warm the engine with stable cost on v2 — no drift, no flip.
        for i in 0..40 {
            let m = PromptMetrics {
                cost_usd: 0.001 + ((i % 5) as f64) * 1e-6,
                latency_ms: 250.0,
                ..Default::default()
            };
            let out = r
                .observe_and_maybe_rollback(
                    t.clone(),
                    "p",
                    Env::Production,
                    v2.prompt_version_id,
                    &m,
                )
                .await
                .unwrap();
            assert!(out.rolled_back_to.is_none());
        }

        // 50× cost spike on v2 → objective drift → auto-flip back to v1.
        let spike = PromptMetrics {
            cost_usd: 0.05,
            latency_ms: 250.0,
            ..Default::default()
        };
        let out = r
            .observe_and_maybe_rollback(
                t.clone(),
                "p",
                Env::Production,
                v2.prompt_version_id,
                &spike,
            )
            .await
            .unwrap();
        assert_eq!(out.decision.mode, Some(RollbackMode::Auto));
        assert_eq!(out.rolled_back_to, Some(v1.prompt_version_id));
        // The production pointer is back to v1 — the loop closed.
        assert_eq!(
            r.route(t.clone(), "p", Env::Production)
                .await
                .unwrap()
                .version_number,
            1
        );
    }

    #[tokio::test]
    async fn subjective_drift_suggests_without_flipping() {
        let r = PromptRouter::new().without_eval_gate();
        let prompt_id = Uuid::from_u128(0x8888);
        let v1 = pv(prompt_id, 1);
        let v2 = pv(prompt_id, 2);
        r.register_version(&tid(71), v1.clone());
        r.register_version(&tid(71), v2.clone());
        let t = tid(71);

        r.promote(
            t.clone(),
            "p",
            Env::Staging,
            Env::Production,
            v1.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();
        r.promote(
            t.clone(),
            "p",
            Env::Staging,
            Env::Production,
            v2.prompt_version_id,
            None,
            None,
        )
        .await
        .unwrap();

        // Warm with stable accuracy + cost.
        for i in 0..40 {
            let m = PromptMetrics {
                cost_usd: 0.001,
                latency_ms: 250.0,
                accuracy: Some(0.92 + ((i % 5) as f64) * 1e-4),
                ..Default::default()
            };
            r.observe_and_maybe_rollback(t.clone(), "p", Env::Production, v2.prompt_version_id, &m)
                .await
                .unwrap();
        }

        // Accuracy plummets — subjective metric → Suggested, no pointer flip.
        let drop = PromptMetrics {
            cost_usd: 0.001,
            latency_ms: 250.0,
            accuracy: Some(0.40),
            ..Default::default()
        };
        let out = r
            .observe_and_maybe_rollback(
                t.clone(),
                "p",
                Env::Production,
                v2.prompt_version_id,
                &drop,
            )
            .await
            .unwrap();
        assert_eq!(out.decision.mode, Some(RollbackMode::Suggested));
        assert!(out.rolled_back_to.is_none());
        // Pointer unchanged — still v2 (human confirms a suggestion).
        assert_eq!(
            r.route(t.clone(), "p", Env::Production)
                .await
                .unwrap()
                .version_number,
            2
        );
    }
}
