//! ClickHouse query wrapper with per-tier resource caps (ADR-031).
//!
//! Every dashboard / gateway read against ClickHouse MUST go through
//! [`TenantQuery::execute`]. The wrapper attaches a `SETTINGS` block
//! with tier-derived `max_memory_usage` + `max_execution_time` +
//! `max_rows_to_read` so a misconfigured query cannot starve the
//! shared CCX23 node for other tenants.
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
/// process environment. **The single CH client constructor for the gateway** —
/// connecting as the default user silently fails every query/insert against a
/// credentialed ClickHouse (ADR-042: the same bug class that crash-looped
/// ingest). Every gateway CH client MUST go through this.
pub(crate) fn ch_client(url: impl Into<String>) -> clickhouse::Client {
    clickhouse::Client::default()
        .with_url(url)
        .with_user(std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()))
        .with_password(std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default())
        .with_database(std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "tracelane".into()))
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
        match key {
            "free_v1" => Self::Free,
            "builder_v1" => Self::Builder,
            "team_v1" => Self::Team,
            "business_v1" => Self::Business,
            "enterprise_v1" => Self::Enterprise,
            _ => Self::Builder,
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
}

impl TenantQuery {
    /// Build a tenant query from the SQL body + the workspace's tier.
    pub fn new(sql: impl Into<String>, tier: PlanTier) -> Self {
        Self {
            sql: sql.into(),
            caps: ClickHouseResourceCaps::for_tier(tier),
        }
    }

    /// Return SQL with the SETTINGS block appended. Idempotent — if
    /// the caller already attached settings, this still works because
    /// later `SETTINGS` clauses override earlier ones in ClickHouse.
    /// We separate the original body from the suffix with a newline
    /// for log-readability.
    pub fn sql_with_settings(&self) -> String {
        // ClickHouse allows multiple SETTINGS sections; later wins.
        // We always append our wrapper's caps last so they cannot be
        // overridden by a query author who attached looser settings.
        format!(
            "{body}\n{settings}",
            body = self.sql.trim_end_matches(';'),
            settings = self.caps.settings_fragment()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
