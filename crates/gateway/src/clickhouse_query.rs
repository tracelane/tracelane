//! ClickHouse query wrapper with per-tier resource caps (ADR-031).
//!
//! Every dashboard / gateway read against ClickHouse MUST go through
//! [`TenantQuery::execute`]. The wrapper attaches a `SETTINGS` block
//! with tier-derived `max_memory_usage` + `max_execution_time` +
//! `max_rows_to_read` so a misconfigured query cannot starve the
//! shared node for other tenants.
//!
//! CI guard `scripts/ci/no-raw-ch-query.sh` enforces that no raw
//! `clickhouse::Client::query` slips outside this wrapper (modulo
//! tests + the ingest write path, which doesn't apply caps).
//!
//! ## Per-tier caps (ADR-031 §Decision)
//!
//! | Tier | Memory | Time | Rows |
//! |---|---|---|---|
//! | Builder | 512 MiB | 10 s | 50 M |
//! | Team | 2 GiB | 30 s | 500 M |
//! | Business | 8 GiB | 60 s | 5 B |
//! | Enterprise | 32 GiB | 300 s | 50 B |
//!
//! Unknown / unresolved tiers fall back to Builder caps (fail-safe).

/// Build a ClickHouse client authenticated as the configured user, reading
/// `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` / `CLICKHOUSE_DB` from the gateway
/// process environment. **The request-path CH client constructor for the gateway** —
/// connecting as the default user silently fails every query/insert against a
/// credentialed ClickHouse (ADR-042: the same bug class that crash-looped
/// ingest). Deletion jobs use `sweeper_client`; all other gateway clients go through this.
pub(crate) fn ch_client(url: impl Into<String>) -> clickhouse::Client {
    clickhouse::Client::default()
        .with_url(url)
        .with_user(std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()))
        .with_password(std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default())
        .with_database(std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "tracelane".into()))
}

/// Deletion-only session for retention and blob GC. Fail-OPEN to the ordinary
/// client if the secret is absent/empty (single-user self-host/dev). In hosted
/// deployments that client cannot delete; callers count the refused mutation.
///
/// # Errors
/// Construction is infallible. An absent/empty secret fails OPEN to `ch_client`;
/// authentication and permission errors surface on execution, CLOSED to deletion.
pub(crate) fn sweeper_client(url: impl Into<String>) -> clickhouse::Client {
    use secrecy::{ExposeSecret, SecretString};
    let password = std::env::var("CLICKHOUSE_SWEEPER_PASSWORD")
        .ok()
        .map(SecretString::from);
    match password.filter(|pw| !pw.expose_secret().is_empty()) {
        Some(password) => clickhouse::Client::default()
            .with_url(url)
            .with_user(
                std::env::var("CLICKHOUSE_SWEEPER_USER").unwrap_or_else(|_| "tl_sweeper".into()),
            )
            .with_password(password.expose_secret())
            .with_database(std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "tracelane".into())),
        None => ch_client(url),
    }
}

/// Read the authenticated session identity (not the configured name).
///
/// # Errors
/// Returns authentication, network or decode errors without inventing an identity
/// (fail-CLOSED to the identity claim). The caller counts the failure and retries.
pub(crate) async fn current_user(
    ch: &clickhouse::Client,
) -> Result<String, clickhouse::error::Error> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct User {
        name: String,
    }
    Ok(ch
        .query(&ceiling("SELECT currentUser() AS name"))
        .fetch_one::<User>()
        .await?
        .name)
}

/// "Now", in the units a ClickHouse `DateTime64(3)` column actually stores.
///
/// **Use this for every `DateTime64(3)` write. Never call `timestamp_micros()`
/// or `timestamp_nanos()` at an insert site.** `clickhouse-rs` maps a plain
/// `i64` straight onto the column's RAW TICKS with no unit conversion, so the
/// precision in the DDL is the only thing that decides what the number means —
/// and getting it wrong is silent. It does not error, it does not truncate; it
/// stores a timestamp roughly a thousand times too large and the row lands in
/// the year ~48000, where nothing queries it and nothing complains.
///
/// **This has now happened twice on the same pair of tables**, which is why it
/// is a shared function rather than a convention:
///
///   1. `promotion_decisions.decided_at` was `timestamp_micros()` — fixed under
///      ADR-054, and the fix records in-source that it was "never verified
///      on-node because promote never ran in prod".
///   2. `rollback_events.fired_at` was `timestamp_micros()` — the exact same
///      overshoot into the exact same sibling table, still unfixed while its
///      twin's fix sat a few files away. Found 2026-08-19.
///
/// Two insert sites agreeing by convention is what allowed the second one. They
/// now agree by construction.
pub(crate) fn datetime64_millis_now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Plan tier identifier — mirrors the Polar/ADR-020 plan keys without
/// pulling in the full billing crate. Constructed from
/// `plan_entitlements.plan_key` strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanTier {
    Free,
    Builder,
    Team,
    Business,
    Enterprise,
}

impl PlanTier {
    /// Parse from a `plan_entitlements.plan_key` string. Unknown
    /// strings fall back to `Builder` so the cap layer is fail-safe
    /// against an unrecognised tier label.
    pub fn from_plan_key(key: &str) -> Self {
        Self::from_known_plan_key(key).unwrap_or(Self::Builder)
    }

    /// The tier for a KNOWN plan key, `None` otherwise — for a caller where an unknown key must
    /// fail CLOSED rather than borrow `from_plan_key`'s cap-layer default (LAST review Low 2).
    pub fn from_known_plan_key(key: &str) -> Option<Self> {
        match key {
            "free_v1" => Some(Self::Free),
            "builder_v1" => Some(Self::Builder),
            "team_v1" => Some(Self::Team),
            "business_v1" => Some(Self::Business),
            "enterprise_v1" => Some(Self::Enterprise),
            _ => None,
        }
    }
}

/// Resource caps attached to every ClickHouse SELECT for a tenant.
/// Numeric fields are in ClickHouse-native units (bytes, seconds,
/// rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClickHouseResourceCaps {
    pub max_memory_usage: u64,
    pub max_execution_time_secs: u32,
    pub max_rows_to_read: u64,
}

impl ClickHouseResourceCaps {
    /// Resolve caps for a plan tier per ADR-031.
    pub const fn for_tier(tier: PlanTier) -> Self {
        match tier {
            // Free is treated as Builder-equivalent for resource caps —
            // there is no separate free-tier ClickHouse cluster; same
            // single-node shared infra applies.
            PlanTier::Free | PlanTier::Builder => Self {
                max_memory_usage: 512 * 1024 * 1024, // 512 MiB
                max_execution_time_secs: 10,
                max_rows_to_read: 50_000_000, // 50 M
            },
            PlanTier::Team => Self {
                max_memory_usage: 2 * 1024 * 1024 * 1024, // 2 GiB
                max_execution_time_secs: 30,
                max_rows_to_read: 500_000_000, // 500 M
            },
            PlanTier::Business => Self {
                max_memory_usage: 8 * 1024 * 1024 * 1024, // 8 GiB
                max_execution_time_secs: 60,
                max_rows_to_read: 5_000_000_000, // 5 B
            },
            PlanTier::Enterprise => Self {
                max_memory_usage: 32u64 * 1024 * 1024 * 1024, // 32 GiB
                max_execution_time_secs: 300,
                max_rows_to_read: 50_000_000_000, // 50 B
            },
        }
    }

    /// Render the caps as a ClickHouse `SETTINGS` fragment. Appended
    /// verbatim to the SQL string by [`TenantQuery::sql_with_settings`].
    pub fn settings_fragment(&self) -> String {
        format!(
            "SETTINGS max_memory_usage = {mem}, max_execution_time = {time}, max_rows_to_read = {rows}",
            mem = self.max_memory_usage,
            time = self.max_execution_time_secs,
            rows = self.max_rows_to_read,
        )
    }
}

/// One tenant-scoped ClickHouse SELECT. Construct with [`Self::new`]
/// and call [`Self::sql_with_settings`] to get the fully-decorated SQL
/// string for submission via the `clickhouse` crate's query path.
#[derive(Debug, Clone)]
pub struct TenantQuery {
    /// SQL body. Caller is responsible for parameter-bound
    /// `tenant_id = ?` placement and parameter binding — this wrapper
    /// only attaches the `SETTINGS` block.
    pub sql: String,
    pub caps: ClickHouseResourceCaps,
    /// BILL-01 / ADR-076 meter 4 — `SETTINGS log_comment = '<tag>'`, read back
    /// from `system.query_log.log_comment` by the daily metering job to
    /// attribute `read_bytes` to a tenant (spec §2.1: "every gateway read is
    /// tagged `tenant_id=<uuid>`"). `None` by default — see
    /// [`Self::with_log_comment`]; an untagged query is simply excluded from
    /// meter 4 (spec's own words: "fail-open on the customer's side, counted
    /// as a defect metric"), never a broken query.
    pub log_comment: Option<String>,
}

impl TenantQuery {
    /// Build a tenant query from the SQL body + the workspace's tier.
    pub fn new(sql: impl Into<String>, tier: PlanTier) -> Self {
        Self {
            sql: sql.into(),
            caps: ClickHouseResourceCaps::for_tier(tier),
            log_comment: None,
        }
    }

    /// Attach a `log_comment` tag. The convention (spec §2.1): a real tenant
    /// read is tagged `tenant_id=<uuid>`; the metering job's OWN queries are
    /// tagged `tracelane-meter`, which the job's `system.query_log` read
    /// explicitly excludes via `log_comment LIKE 'tenant_id=%'`.
    #[must_use]
    pub fn with_log_comment(mut self, tag: impl Into<String>) -> Self {
        self.log_comment = Some(tag.into());
        self
    }

    /// Return SQL with one SETTINGS block appended. The input must NOT already
    /// contain SETTINGS: ClickHouse 24.12 rejects a second clause (retention
    /// hardening real-server test). Put other settings in query.with_option().
    /// We separate the original body from the suffix with a newline
    /// for log-readability.
    pub fn sql_with_settings(&self) -> String {
        // One SETTINGS clause only; callers supply an undecorated SQL body.
        let mut settings = self.caps.settings_fragment();
        if let Some(tag) = &self.log_comment {
            // Single-quoted ClickHouse string literal; a literal `'` in a
            // tag (never true for our own `tenant_id=<uuid>` / fixed-string
            // tags, but defensive against a future caller) is escaped by
            // doubling, ClickHouse's own escape convention.
            settings.push_str(&format!(", log_comment = '{}'", tag.replace('\'', "''")));
        }
        format!("{body}\n{settings}", body = self.sql.trim_end_matches(';'),)
    }
}

/// Split a ClickHouse migration file into executable statements, for tests.
///
/// **Comments are stripped BEFORE the split, and that ordering is the whole
/// point.** `17_semantic_cache.sql:40` carries a trailing comment INSIDE the
/// column list — *"What a hit saves; never re-charged."* — and that semicolon
/// splits the `CREATE TABLE` in half. The server then reports
/// *"Unmatched parentheses"* against a fragment that begins with `(`, which
/// reads like a broken migration rather than a broken test.
///
/// `crates/gateway/tests/clickhouse_persister_integration.rs` splits first and
/// filters `starts_with("--")` after, so it sends a comment block as SQL and
/// dies with a syntax error at *position 1 ('the')*. It has had ZERO callers
/// since it was written, so nothing ever ran it — `docs/reference/TRAPS.md` §1
/// CLASS-1, the same shape `run-postgres-integration.sh` was created to close.
/// The ADR-031 cap tier for THIS tenant — its own plan, read from the entitlement
/// cache the hot path already keeps (no Postgres per request). SRE register #20
/// (2026-09-05): after B-330 made `trace_reads.rs` tier-aware, ~47 other reads still
/// passed the literal `PlanTier::Builder`, so a Team or Business tenant queried
/// datasets, experiments, evals, the audit export and the semantic cache under
/// Builder's caps whatever it paid for. One helper, so every reader resolves the
/// tier the same way. Fails CLOSED (`.claude/rules/tenancy.md`): no control plane →
/// `Free`; an unknown plan key → the conservative default `from_plan_key` carries.
pub async fn tier_for_tenant(
    entitlements: Option<&std::sync::Arc<crate::entitlement_cache::EntitlementCache>>,
    tenant_id: &tracelane_shared::TenantId,
) -> PlanTier {
    match entitlements {
        None => PlanTier::Free,
        Some(cache) => {
            let resolved = cache.resolved(*tenant_id.as_uuid()).await;
            PlanTier::from_plan_key(&resolved.plan_lookup_key)
        }
    }
}

/// A CEILING for reads that have no tenant tier to resolve — background sweeps,
/// cross-tenant boot loads, the alert checker, the audit anchor jobs. SRE #20
/// follow-up (2026-09-06): `check-ch-reads-capped.py` found two dozen such reads
/// with NO settings at all. Business caps (60 s / 5 B rows / 8 GiB): a bound where
/// none existed, wide enough that no legitimate sweep on today's data can trip it,
/// and NOT Enterprise, whose 32 GiB memory cap exceeds the box and bounds nothing.
#[must_use]
pub fn ceiling(sql: &str) -> String {
    TenantQuery::new(sql, PlanTier::Business).sql_with_settings()
}

/// A tenant-filtered `count()` lookup, capped per the tenant's tier (ADR-031): `sql` must
/// take exactly two binds — the tenant id, then `id` — and select one `n: UInt64` column.
/// Lives in this wrapper so callers (the OG-06 batch provenance + spend-dedup lookups) never
/// touch the ClickHouse client directly (`no-raw-ch-query.sh`).
///
/// # Errors
/// Returns the ClickHouse error; the CALLER decides fail-closed vs fail-open (§10).
pub(crate) async fn tenant_count_by_id(
    url: String,
    tier: PlanTier,
    sql: &str,
    tenant_id: &tracelane_shared::TenantId,
    id: &str,
) -> Result<u64, clickhouse::error::Error> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    let sql = TenantQuery::new(sql, tier).sql_with_settings();
    ch_client(url)
        .query(&sql)
        .bind(tenant_id.to_string())
        .bind(id)
        .fetch_one::<CountRow>()
        .await
        .map(|r| r.n)
}

/// [`tenant_count_by_id`] with several bound values after the tenant (`OG-20`'s batch
/// provenance binds the file id, the key id and the policy fingerprint).
pub(crate) async fn tenant_count_by_ids(
    url: String,
    tier: PlanTier,
    sql: &str,
    tenant_id: &tracelane_shared::TenantId,
    ids: &[&str],
) -> Result<u64, clickhouse::error::Error> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    let sql = TenantQuery::new(sql, tier).sql_with_settings();
    let mut q = ch_client(url).query(&sql).bind(tenant_id.to_string());
    for id in ids {
        q = q.bind(*id);
    }
    q.fetch_one::<CountRow>().await.map(|r| r.n)
}

#[cfg(test)]
pub(crate) fn split_migration_statements(sql: &str) -> Vec<String> {
    let stripped: String = sql
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    stripped
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL; integration runner or isolated credential proof"]
    async fn sweeper_identity_against_a_real_clickhouse() {
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("throwaway URL required");
        let expected =
            std::env::var("SWEEPER_TEST_EXPECTED_USER").unwrap_or_else(|_| "default".into());
        // The client's default database is `tracelane`; create it first so this test does
        // not depend on another test having run (it failed whenever it ran first, 2026-09-30).
        // As the admin the environment names (the users proof's prod-shaped container has
        // no anonymous `default` user); the integration runner sets none and uses default.
        let mut admin = clickhouse::Client::default().with_url(url.clone());
        if let (Ok(user), Ok(password)) = (
            std::env::var("CLICKHOUSE_USER"),
            std::env::var("CLICKHOUSE_PASSWORD"),
        ) {
            admin = admin.with_user(user).with_password(password);
        }
        admin
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create tracelane database");
        let actual = current_user(&sweeper_client(url))
            .await
            .expect("authenticated identity");
        assert_eq!(actual, expected);
    }

    #[test]
    fn plan_tier_from_plan_key_known_strings() {
        assert_eq!(PlanTier::from_plan_key("free_v1"), PlanTier::Free);
        assert_eq!(PlanTier::from_plan_key("builder_v1"), PlanTier::Builder);
        assert_eq!(PlanTier::from_plan_key("team_v1"), PlanTier::Team);
        assert_eq!(PlanTier::from_plan_key("business_v1"), PlanTier::Business);
        assert_eq!(
            PlanTier::from_plan_key("enterprise_v1"),
            PlanTier::Enterprise
        );
    }

    #[test]
    fn unknown_plan_key_falls_back_to_builder() {
        // Fail-safe behaviour per ADR-031: an unrecognised tier label
        // never gets Enterprise-class caps.
        assert_eq!(PlanTier::from_plan_key("bogus"), PlanTier::Builder);
        assert_eq!(PlanTier::from_plan_key(""), PlanTier::Builder);
    }

    #[test]
    fn caps_match_adr_031_table() {
        let b = ClickHouseResourceCaps::for_tier(PlanTier::Builder);
        assert_eq!(b.max_memory_usage, 512 * 1024 * 1024);
        assert_eq!(b.max_execution_time_secs, 10);
        assert_eq!(b.max_rows_to_read, 50_000_000);

        let t = ClickHouseResourceCaps::for_tier(PlanTier::Team);
        assert_eq!(t.max_memory_usage, 2 * 1024 * 1024 * 1024);
        assert_eq!(t.max_execution_time_secs, 30);
        assert_eq!(t.max_rows_to_read, 500_000_000);

        let b2 = ClickHouseResourceCaps::for_tier(PlanTier::Business);
        assert_eq!(b2.max_memory_usage, 8 * 1024 * 1024 * 1024);
        assert_eq!(b2.max_execution_time_secs, 60);
        assert_eq!(b2.max_rows_to_read, 5_000_000_000);

        let e = ClickHouseResourceCaps::for_tier(PlanTier::Enterprise);
        assert_eq!(e.max_memory_usage, 32u64 * 1024 * 1024 * 1024);
        assert_eq!(e.max_execution_time_secs, 300);
        assert_eq!(e.max_rows_to_read, 50_000_000_000);
    }

    #[test]
    fn caps_are_monotonic_across_tiers() {
        // Sanity: every cap grows monotonically Builder → Team → Business → Enterprise.
        // A regression that swaps two tiers in `for_tier` is caught here.
        let tiers = [
            PlanTier::Builder,
            PlanTier::Team,
            PlanTier::Business,
            PlanTier::Enterprise,
        ];
        let caps: Vec<_> = tiers
            .iter()
            .map(|t| ClickHouseResourceCaps::for_tier(*t))
            .collect();
        for w in caps.windows(2) {
            assert!(w[1].max_memory_usage > w[0].max_memory_usage);
            assert!(w[1].max_execution_time_secs > w[0].max_execution_time_secs);
            assert!(w[1].max_rows_to_read > w[0].max_rows_to_read);
        }
    }

    #[test]
    fn settings_fragment_renders_clickhouse_syntax() {
        let caps = ClickHouseResourceCaps::for_tier(PlanTier::Builder);
        let s = caps.settings_fragment();
        assert!(s.starts_with("SETTINGS "));
        assert!(s.contains("max_memory_usage = 536870912"));
        assert!(s.contains("max_execution_time = 10"));
        assert!(s.contains("max_rows_to_read = 50000000"));
    }

    #[test]
    fn tenant_query_appends_settings_to_body() {
        let q = TenantQuery::new(
            "SELECT count() FROM tracelane.spans WHERE tenant_id = {tid:UUID}",
            PlanTier::Team,
        );
        let sql = q.sql_with_settings();
        assert!(sql.contains("WHERE tenant_id"));
        assert!(sql.contains("SETTINGS max_memory_usage = 2147483648"));
        // Newline-separated for log-readability.
        assert!(sql.contains("\nSETTINGS"));
    }

    /// BILL-01 / ADR-076 meter 4 (step 5): the rendered SQL carries the
    /// `log_comment` tag inside the SAME `SETTINGS` clause, so meter 4's
    /// `system.query_log.log_comment LIKE 'tenant_id=%'` read can attribute
    /// this query — and a query with no tag attached renders none, which is
    /// the fail-open-on-the-customer's-side default the spec names.
    #[test]
    fn with_log_comment_renders_the_tag_in_the_settings_clause() {
        let tagged = TenantQuery::new("SELECT 1", PlanTier::Team)
            .with_log_comment("tenant_id=00000000-0000-0000-0000-000000000001");
        let sql = tagged.sql_with_settings();
        assert!(
            sql.contains("log_comment = 'tenant_id=00000000-0000-0000-0000-000000000001'"),
            "rendered SQL must carry the log_comment tag: {sql}"
        );
        assert!(
            sql.contains("SETTINGS max_memory_usage"),
            "caps must still be present"
        );

        let untagged = TenantQuery::new("SELECT 1", PlanTier::Team).sql_with_settings();
        assert!(
            !untagged.contains("log_comment"),
            "no tag attached must render no log_comment clause"
        );
    }

    #[test]
    fn tenant_query_strips_trailing_semicolon_before_settings() {
        // ClickHouse rejects a `;` between the query body and a
        // SETTINGS clause. The wrapper strips a trailing semicolon
        // from the caller's body so an over-eager query author doesn't
        // get a parse error from our wrapper.
        let q = TenantQuery::new("SELECT 1;", PlanTier::Builder);
        let sql = q.sql_with_settings();
        assert!(!sql.contains("1;"), "trailing semicolon must be stripped");
        assert!(sql.contains("SETTINGS"));
    }

    /// SRE register #20 (2026-09-05): no reader outside this file passes the literal
    /// Builder tier any more — every one resolves the tenant's own tier through
    /// `tier_for_tenant`. Scans the NON-TEST half of each file that used to carry the
    /// literal (B-330 covered `trace_reads.rs` the same way). The needle is built with
    /// `concat!` so this test's own source cannot satisfy it.
    #[test]
    fn no_reader_passes_the_builder_tier_literal_any_more() {
        let needle = concat!("PlanTier::", "Builder");
        let files: [(&str, &str); 10] = [
            ("audit_export.rs", include_str!("audit_export.rs")),
            ("dataset_routes.rs", include_str!("dataset_routes.rs")),
            ("experiment_routes.rs", include_str!("experiment_routes.rs")),
            ("prompt_eval.rs", include_str!("prompt_eval.rs")),
            (
                "online_eval_routes.rs",
                include_str!("online_eval_routes.rs"),
            ),
            ("online_eval.rs", include_str!("online_eval.rs")),
            ("semantic_cache.rs", include_str!("semantic_cache.rs")),
            ("spend.rs", include_str!("spend.rs")),
            ("annotation_routes.rs", include_str!("annotation_routes.rs")),
            ("tool_analytics.rs", include_str!("tool_analytics.rs")),
        ];
        for (name, src) in files {
            let non_test = src.split("#[cfg(test)]").next().unwrap_or("");
            assert!(
                !non_test.contains(needle),
                "{name} still passes the literal Builder tier outside its tests — use \
                 tier_for_tenant / the reader's tier_for (SRE #20)"
            );
        }
    }
}
