//! Is this Postgres host able to deliver `NOTIFY`?
//!
//! **.** Both control-plane `LISTEN` tasks — `gateway::entitlement_cache`
//! and `ingest::tenant_config` — resolve their DSN as
//! `POSTGRES_DIRECT_URL` **or else** `POSTGRES_URL`, so the "disabled" branch is
//! reached only when *both* are unset. With the ordinary Neon config
//! (`POSTGRES_URL` set to the `-pooler` endpoint, `POSTGRES_DIRECT_URL` unset)
//! the listener connects to PgBouncer, issues `LISTEN` — which **succeeds**, the
//! statement is valid — and then logs `LISTEN active` on a socket that can never
//! carry a notification. Transaction pooling hands the backend to another client
//! between statements, so the `NOTIFY` has nowhere to land.
//!
//! Nothing errors. Invalidation silently degrades to the 15-minute TTL, which
//! means **a revoked API key keeps working for up to 15 minutes** while an INFO
//! line asserts the opposite. Same shape as one layer down: listening on a
//! socket that will never deliver, and saying so in the log.
//!
//! **Why a host predicate and not a "is `POSTGRES_DIRECT_URL` set?" check.** A
//! self-hosted or OSS Postgres has exactly one URL, no PgBouncer in front of it,
//! and carries `NOTIFY` perfectly well. Refusing or warning there would break a
//! valid deployment to fix a Neon-specific misconfiguration. The thing that
//! cannot deliver is the *pooler*, so the pooler is what we detect.
//!
//! **Why the host, not the DSN string.** A password may contain arbitrary
//! characters, `-pooler` included, so `dsn.contains("-pooler")` can false-positive
//! on a correctly-configured direct endpoint. Callers pass the host they already
//! parsed out of `tokio_postgres::Config::get_hosts()`.

/// True when `host` is a connection POOLER that cannot deliver `NOTIFY`.
///
/// Known shapes, all matched on the host label rather than a bare substring so a
/// hostname that merely *contains* the word does not trip it:
/// - Neon:     `ep-xxx-pooler.<region>.aws.neon.tech`
/// - Supabase: `aws-0-<region>.pooler.supabase.com`
/// - A PgBouncer sidecar conventionally named `pgbouncer` / `pgbouncer.<ns>`
///
/// Conservative by construction: an unknown pooler reads as direct, so this can
/// under-report but never fabricate a degradation on a healthy direct endpoint.
/// Under-reporting leaves today's behaviour exactly as it is; over-reporting
/// would cry wolf on every self-host, which is how a warning gets ignored.
#[must_use]
pub fn host_cannot_deliver_notify(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    let first_label = h.split('.').next().unwrap_or("");
    first_label.ends_with("-pooler")
        || first_label == "pooler"
        || first_label == "pgbouncer"
        || h.split('.').any(|label| label == "pooler")
}

#[cfg(test)]
mod tests {
    use super::host_cannot_deliver_notify;

    #[test]
    fn neon_pooler_endpoint_is_detected() {
        assert!(host_cannot_deliver_notify(
            "ep-cool-frost-123456-pooler.eu-central-1.aws.neon.tech"
        ));
    }

    #[test]
    fn supabase_pooler_endpoint_is_detected() {
        assert!(host_cannot_deliver_notify(
            "aws-0-eu-central-1.pooler.supabase.com"
        ));
    }

    #[test]
    fn bare_pgbouncer_sidecar_is_detected() {
        assert!(host_cannot_deliver_notify("pgbouncer"));
        assert!(host_cannot_deliver_notify("pgbouncer.control-plane.svc"));
    }

    #[test]
    fn neon_direct_endpoint_is_not_a_pooler() {
        assert!(!host_cannot_deliver_notify(
            "ep-cool-frost-123456.eu-central-1.aws.neon.tech"
        ));
    }

    #[test]
    fn plain_and_self_hosted_hosts_are_not_poolers() {
        assert!(!host_cannot_deliver_notify("localhost"));
        assert!(!host_cannot_deliver_notify("postgres"));
        assert!(!host_cannot_deliver_notify("db.internal.example.com"));
        assert!(!host_cannot_deliver_notify("10.0.0.7"));
    }

    /// The negative that motivates matching a LABEL rather than a substring: a
    /// direct endpoint whose name merely contains the word must not be degraded.
    #[test]
    fn substring_lookalikes_do_not_false_positive() {
        assert!(!host_cannot_deliver_notify("pooler-metrics.example.com"));
        assert!(!host_cannot_deliver_notify("db-poolerless.example.com"));
        assert!(!host_cannot_deliver_notify("mypooler.example.com"));
    }

    #[test]
    fn case_and_whitespace_do_not_defeat_it() {
        assert!(host_cannot_deliver_notify(
            "  EP-X-POOLER.eu-central-1.AWS.neon.tech "
        ));
    }
}
