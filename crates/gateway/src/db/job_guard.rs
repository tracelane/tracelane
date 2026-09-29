//! `RI-04` — a per-job cross-process leader claim, generalising the audit
//! anchor sweep's advisory-lock shape (`audit.rs:587-611`, the claim itself at
//! `audit.rs:611`, `tenant_advisory_key` at `audit.rs:1818-1824`) into one
//! helper any scheduled background job can call.
//!
//! # Why
//!
//! ADR-077 step 1 wants a second gateway process behind Caddy. Ruling F'
//! (2026-09-19, `specs/RI-04-background-singletons-and-leader-guards.md`)
//! refused that until every background job that would otherwise run TWICE
//! per tick — once per process — has a guard. Three jobs qualify today:
//! `retention_sweep` (a heavy per-tenant ClickHouse mutation), `metering_daily`
//! (9 ClickHouse reads + Polar POSTs + a usage-warning email), `blob_gc` (a
//! weekly `ALTER … DELETE`). None of the three is a CORRECTNESS hazard under
//! two processes today — the spec's finding 1 is that no background job
//! writes the one Summing table (`meter_counters`) the ruling was worried
//! about, and each of these three is idempotent or produces the same result
//! run twice (spec §2a) — but doubling that work on every tick is a real cost
//! this closes for free, and the NEXT job that writes a computed total needs
//! this to already exist rather than re-deriving it (§3 option (c)'s limit:
//! per-job idempotency proves nothing about the next job).
//!
//! B-428 (2026-09-19) is the fail-closed-but-LOUD reading this carries over
//! from the anchor sweep, verbatim: a probe error is "cannot tell", never
//! "someone else has it" — the anchor sweep's first cut folded every failure
//! on the way to its claim into a silent skip, which would have left every
//! aged batch un-anchored forever with no line saying why. The direction
//! (skip on doubt) stays; the silence does not.
//!
//! # How
//!
//! `pg_try_advisory_xact_lock($1::int4, hashtext($2::text))` — a
//! TRANSACTION-scoped advisory lock, released on COMMIT, ROLLBACK, or the
//! transaction being dropped, so a panic mid-run can never leave a job
//! claimed forever the way a SESSION-scoped lock could (`db::singleton`'s
//! lock is deliberately session-scoped instead, for the opposite reason: it
//! must survive for the process lifetime). [`JOB_CLASS`] is a FIXED classid,
//! so this two-int4 keyspace can never collide with
//! `audit::tenant_advisory_key`'s single-bigint keyspace — Postgres keeps the
//! 64-bit and the 32+32-bit advisory-lock forms in genuinely separate
//! namespaces, not merely different values sharing one.
//!
//! This adds **no poller and no new session** (B-442: a poller — a query
//! running on its own clock, independent of real work — is what pins a Neon
//! compute awake; a session that only ever opens alongside work the job was
//! about to do anyway is not one). The claim rides the SAME tick the job
//! would have run on regardless: get one pooled client, try the lock, run or
//! skip. Zero new claims/week for the daily and boot-catch-up sites (they ride
//! `metering_job::run_once`'s own cadence); one new query a week for the GC
//! tick (spec §5).
//!
//! # The three outcomes
//!
//! - **[`Claim::Won`]** — this process claimed the cadence. Run the job, then
//!   drop (or commit) the transaction; either releases the lock, and a
//!   rollback (a bare `drop`) is the right choice at every call site here
//!   because nothing is ever WRITTEN through this transaction — it exists
//!   only to scope the lock's lifetime, exactly like the anchor sweep's.
//! - **[`Claim::Lost`]** — another process already holds it. Normal and
//!   expected the moment a second gateway exists; logged at `debug!` only —
//!   promoting this to a counted degradation would make the everyday
//!   steady-state of TWO processes page someone.
//! - **[`Claim::CannotTell`]** — the pool, the transaction, or the lock probe
//!   itself failed. Counted under [`Degradation::JobClaimFailed`] and logged
//!   LOUD before this is returned, because a Postgres that always fails this
//!   probe would otherwise stop every guarded job forever with no signal at
//!   all — indistinguishable from "the other process is always the one that
//!   wins", which is not what happened.
//!
//! Callers get exactly these three outcomes from [`claim`] and never a fourth
//! "and also it might error" case — every failure path is folded into
//! `CannotTell` before it reaches the caller.

use deadpool_postgres::Transaction;

/// Fixed classid for every job claim in this process — the first argument to
/// the two-int4 `pg_try_advisory_xact_lock` overload. A job's actual identity
/// is `hashtext(job_name)`, the second argument; this constant exists ONLY so
/// that keyspace can never be reached by `audit::tenant_advisory_key`'s
/// single-bigint-argument locks, which Postgres keeps in a wholly separate
/// namespace from the two-int4 form regardless of which values either side
/// picks. Value is arbitrary and stable: the big-endian bytes of the ASCII
/// tag `"TLJB"` ("TraceLane JoB"), pinned by a unit test so a future edit
/// cannot silently change the keyspace a running deploy already has claims
/// pending against.
pub const JOB_CLASS: i32 = 0x544C_4A42;

/// The outcome of one [`claim`] attempt.
pub enum Claim<'a> {
    /// This process holds the advisory lock for the claimed job, scoped to
    /// `tx`. Run the job, then drop (releases via an implicit ROLLBACK — the
    /// right choice, since nothing is ever written through this transaction)
    /// or explicitly `tx.commit()` (equivalent here); either releases the
    /// lock.
    Won(Transaction<'a>),
    /// Another process holds the lock right now. Ordinary the moment two or
    /// more gateway processes exist; skip this cadence, nothing to log beyond
    /// `debug!`.
    Lost,
    /// The pool, the transaction, or the lock probe itself failed — this is
    /// NOT "someone else has it" (B-428). Skip this cadence; already logged
    /// and counted under [`Degradation::JobClaimFailed`] before this is
    /// returned, so a caller never needs to instrument this arm itself.
    CannotTell,
}

/// Pure mapping from the advisory-lock probe's result to an outcome — no I/O,
/// no logging, no `Transaction`, no database. This is what proof 1 (spec §7)
/// tests directly; [`claim`] calls it and then attaches the transaction,
/// warns, and counts around whichever arm comes back, so the mapping itself
/// stays a single, testable decision rather than three copies of the same
/// `match` (one real, two in tests asserting it separately).
enum Decision<E> {
    Won,
    Lost,
    CannotTell(E),
}

fn decide<E>(probe: Result<bool, E>) -> Decision<E> {
    match probe {
        Ok(true) => Decision::Won,
        Ok(false) => Decision::Lost,
        Err(e) => Decision::CannotTell(e),
    }
}

/// Try to claim `job` for this tick on the existing connection pool.
///
/// Opens a transaction on `client` purely to scope the advisory lock's
/// lifetime — nothing is ever written through it — and asks Postgres whether
/// this process now holds `(JOB_CLASS, hashtext(job))`. `client` is a pooled
/// connection the CALLER gets from the job's own `&DbPool` (`pool.get().await`)
/// **separate from any connection the job itself uses to do its work** — the
/// returned `Won(Transaction)` borrows `client` mutably for as long as the
/// claim is held, so the job's own reads/writes go through the `&DbPool`
/// directly, never through this borrowed client.
///
/// # Errors
/// Infallible in the `Result` sense — see [`Claim::CannotTell`], which is
/// this function's only fail-closed-but-loud path and is counted before
/// return. Never panics: no `unwrap`/`expect` on any branch.
pub async fn claim<'a>(client: &'a mut deadpool_postgres::Client, job: &str) -> Claim<'a> {
    let tx = match client.transaction().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::warn!(
                job,
                error = %err,
                "job_guard: could not open the claim transaction — cannot tell who holds it, \
                 skipping this cadence"
            );
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::JobClaimFailed,
            );
            return Claim::CannotTell;
        }
    };
    let probe = tx
        .query_one(
            "SELECT pg_try_advisory_xact_lock($1::int4, hashtext($2::text))",
            &[&JOB_CLASS, &job],
        )
        .await
        .map(|row| row.get::<_, bool>(0));
    match decide(probe) {
        Decision::Won => {
            let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into());
            tracing::info!(job, leader = %hostname, "job claim won");
            Claim::Won(tx)
        }
        Decision::Lost => {
            tracing::debug!(job, "job_guard: another process already holds this cadence");
            Claim::Lost
        }
        Decision::CannotTell(err) => {
            // A probe ERROR is not "held elsewhere" — it is "cannot tell", and the
            // only safe reading is to skip this cadence rather than guess (B-428,
            // the same shape as the anchor sweep's own claim at `audit.rs:611`).
            tracing::warn!(
                job,
                error = %err,
                "job_guard: advisory-lock probe FAILED — treating as cannot-tell, skipping \
                 this cadence"
            );
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::JobClaimFailed,
            );
            Claim::CannotTell
        }
    }
}

/// The one call a scheduled job makes: get a pooled client, claim `job`, run `f`
/// only on [`Claim::Won`], release the lock by dropping the transaction (a
/// ROLLBACK — nothing is ever written through it), and tell the caller whether it
/// ran. `None` covers BOTH a lost claim and a failed one: the difference is
/// already logged and counted inside [`claim`], and to the caller both mean
/// "nothing happened here this cadence" — neither a clean run nor a failure, so
/// a caller's own success/failure bookkeeping (`resolve_after_clean_run`) must
/// not move on it. A pool failure is counted here as [`Degradation::JobClaimFailed`]
/// for the same B-428 reason `claim` counts its own: a Postgres that refuses the
/// pool on every tick would otherwise stop every guarded job in silence.
///
/// `f` borrows nothing from this function — the job does its own work through its
/// own `&DbPool` connections, never through the claim's client.
///
/// # Errors
/// None returned — fail-OPEN in the CLAUDE.md §10 sense: every failure here means
/// "skip this cadence", never "block anything".
pub async fn run_claimed<F, Fut, T>(pool: &crate::db::DbPool, job: &str, f: F) -> Option<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let mut client = match pool.get().await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(
                job,
                error = %err,
                "job_guard: could not get a Postgres connection for the claim — skipping this cadence"
            );
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::JobClaimFailed,
            );
            return None;
        }
    };
    match claim(&mut client, job).await {
        Claim::Won(tx) => {
            let out = f().await;
            drop(tx);
            Some(out)
        }
        Claim::Lost | Claim::CannotTell => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proof 1 (spec §7) — the WON/LOST/CANNOT-TELL mapping is pure and needs
    /// no database. `claim` itself cannot be unit-tested directly (it needs a
    /// real `deadpool_postgres::Client` to open a transaction on); this is the
    /// exact `decide` it calls, so a real-Postgres run (proof 2,
    /// `postgres_tenant_integration.rs`) only has to prove the PROBE reaches
    /// the right `Result`, not re-prove this mapping.
    #[test]
    fn probe_true_wins_false_loses_error_cannot_tell() {
        assert!(matches!(decide::<&str>(Ok(true)), Decision::Won));
        assert!(matches!(decide::<&str>(Ok(false)), Decision::Lost));
        assert!(matches!(
            decide(Err::<bool, _>("pg down")),
            Decision::CannotTell("pg down")
        ));
    }

    /// The classid is a stable wire-adjacent value once a deploy has claims
    /// pending against it — pin the exact bytes so a future edit here is a
    /// deliberate keyspace change, not an accidental one.
    #[test]
    fn job_class_is_the_stable_tljb_ascii_tag() {
        assert_eq!(JOB_CLASS.to_be_bytes(), *b"TLJB");
    }
}
