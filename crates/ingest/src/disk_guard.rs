//! FT-08 — self-host disk-full graceful degradation.
//!
//! On a self-hosted node (Tracelane Lite single-binary, or any ingest box
//! whose local volume backs NATS spill / WAL / temp), a full disk must not
//! crash or panic the ingest process. Instead the node sheds **new** spans
//! with a structured `507 Insufficient Storage` + `storage.disk_full=true`
//! alert, while already-ingested data and the (ClickHouse-backed) read path
//!
//! Hot-path discipline: the receiver checks a single `AtomicBool`
//! (`is_shedding`) — no `statvfs` syscall per request. A background task
//! ([`DiskGuard::run_refresher`]) re-evaluates free space every
//! [`REFRESH_INTERVAL`] and flips the flag. Fail-open per the FT rule in
//! `.claude/rules/rust.md`: if `statvfs` errors we do NOT shed (a transient
//! stat failure must not wrongly reject healthy traffic).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Minimum free bytes below which the node sheds new spans. 100 MiB matches
pub const DEFAULT_MIN_FREE_BYTES: u64 = 100 * 1024 * 1024;

/// How often the background task re-checks free disk. Off the hot path.
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Process-wide count of spans shed because the disk was full (FT-08).
/// Exported for the metrics endpoint alongside the ADR-029 reject counters.
static DISK_SHED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Record that a batch was shed due to disk pressure.
pub fn record_disk_shed() {
    DISK_SHED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot the disk-shed counter (test + metrics).
pub fn disk_shed_total() -> u64 {
    DISK_SHED_TOTAL.load(Ordering::Relaxed)
}

/// Pure admission decision: shed when free space is below the floor.
///
/// Kept separate from the syscall so FT-08 can test the policy
/// deterministically without manipulating a real filesystem.
#[must_use]
pub fn should_shed(available_bytes: u64, min_free_bytes: u64) -> bool {
    available_bytes < min_free_bytes
}

/// Bytes available to an unprivileged writer on the filesystem holding
/// `path`. `f_bavail` (not `f_bfree`) so reserved-root blocks aren't counted
/// as usable.
///
/// # Errors
/// Propagates the `statvfs` error (path missing, permission denied, ENOSYS
/// on an exotic target).
pub fn available_bytes(path: &Path) -> std::io::Result<u64> {
    let s = rustix::fs::statvfs(path)?;
    Ok(s.f_bavail.saturating_mul(s.f_frsize))
}

/// Shared disk-pressure flag plus the refresher that maintains it.
///
/// Cheap to clone (the flag is an `Arc<AtomicBool>`); the receiver holds one
/// clone and the background task another.
#[derive(Clone)]
pub struct DiskGuard {
    shedding: Arc<AtomicBool>,
    data_dir: PathBuf,
    min_free_bytes: u64,
}

impl DiskGuard {
    /// Construct from env: `TRACELANE_INGEST_DATA_DIR` (default `.`) and
    /// `TRACELANE_INGEST_MIN_FREE_BYTES` (default 100 MiB). Runs one eager
    /// check so the flag is correct before the first request.
    #[must_use]
    pub fn from_env() -> Self {
        let data_dir = std::env::var_os("TRACELANE_INGEST_DATA_DIR")
            .map_or_else(|| PathBuf::from("."), PathBuf::from);
        let min_free_bytes = std::env::var("TRACELANE_INGEST_MIN_FREE_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MIN_FREE_BYTES);
        Self::new(data_dir, min_free_bytes)
    }

    /// Construct with explicit settings and run one eager check.
    #[must_use]
    pub fn new(data_dir: PathBuf, min_free_bytes: u64) -> Self {
        let guard = Self {
            shedding: Arc::new(AtomicBool::new(false)),
            data_dir,
            min_free_bytes,
        };
        guard.refresh_once();
        guard
    }

    /// Is the node currently shedding new spans? Single atomic load — safe to
    /// call on the hot path per request.
    #[must_use]
    pub fn is_shedding(&self) -> bool {
        self.shedding.load(Ordering::Acquire)
    }

    /// Re-evaluate free disk and update the flag once. Fail-open: a `statvfs`
    /// error leaves the flag unchanged (does not start shedding).
    pub fn refresh_once(&self) {
        match available_bytes(&self.data_dir) {
            Ok(avail) => {
                let shed = should_shed(avail, self.min_free_bytes);
                let was = self.shedding.swap(shed, Ordering::Release);
                if shed && !was {
                    tracing::error!(
                        data_dir = %self.data_dir.display(),
                        available_bytes = avail,
                        min_free_bytes = self.min_free_bytes,
                        "storage.disk_full=true — ingest entering SHED mode; new spans \
                         will be rejected with 507 until disk is freed (FT-08)",
                    );
                } else if !shed && was {
                    tracing::warn!(
                        data_dir = %self.data_dir.display(),
                        available_bytes = avail,
                        "storage.disk_full=false — disk recovered; ingest resuming normal admission",
                    );
                }
            }
            Err(err) => {
                // Fail-open: do NOT shed on a stat failure.
                tracing::warn!(
                    data_dir = %self.data_dir.display(),
                    error = %err,
                    "disk-space check failed; leaving admission unchanged (fail-open)",
                );
            }
        }
    }

    /// Background refresher: re-check free disk every [`REFRESH_INTERVAL`].
    /// Never returns under normal operation; folded into the ingest
    /// `try_join!` so a panic here surfaces.
    pub async fn run_refresher(self) -> anyhow::Result<()> {
        let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            data_dir = %self.data_dir.display(),
            min_free_bytes = self.min_free_bytes,
            "disk-pressure refresher started (FT-08)",
        );
        loop {
            ticker.tick().await;
            self.refresh_once();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_shed_below_floor_only() {
        assert!(should_shed(50 * 1024 * 1024, DEFAULT_MIN_FREE_BYTES));
        assert!(!should_shed(200 * 1024 * 1024, DEFAULT_MIN_FREE_BYTES));
        // Boundary: exactly at the floor is NOT shed (strictly-below).
        assert!(!should_shed(DEFAULT_MIN_FREE_BYTES, DEFAULT_MIN_FREE_BYTES));
        assert!(should_shed(
            DEFAULT_MIN_FREE_BYTES - 1,
            DEFAULT_MIN_FREE_BYTES
        ));
    }

    #[test]
    fn available_bytes_reports_positive_for_real_dir() {
        let tmp = std::env::temp_dir();
        let avail = available_bytes(&tmp).expect("statvfs on temp dir");
        assert!(avail > 0, "a writable temp dir must report some free space");
    }

    /// FT-08 core: a threshold above total capacity faithfully simulates a
    /// full disk (free < floor). The guard flips to SHED and the syscall +
    /// decision logic are exercised for real — no tmpfs quota needed.
    #[test]
    fn guard_sheds_when_threshold_exceeds_capacity() {
        let full = DiskGuard::new(std::env::temp_dir(), u64::MAX);
        assert!(full.is_shedding(), "free space is always < u64::MAX → shed");

        let healthy = DiskGuard::new(std::env::temp_dir(), 0);
        assert!(!healthy.is_shedding(), "min_free=0 can never shed");
    }

    /// Recovery: a guard that was shedding clears the flag once free space is
    /// back above the floor (here, lowering the floor to 0 then refreshing).
    #[test]
    fn guard_recovers_after_disk_frees() {
        let mut guard = DiskGuard::new(std::env::temp_dir(), u64::MAX);
        assert!(guard.is_shedding());
        // Simulate the disk freeing by relaxing the floor, then refresh.
        guard.min_free_bytes = 0;
        guard.refresh_once();
        assert!(
            !guard.is_shedding(),
            "guard must resume admission on recovery"
        );
    }
}
