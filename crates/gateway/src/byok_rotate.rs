//! `gateway byok-rotate` — re-wrap every BYOK-encrypted row under the ACTIVE KEK
//! (B-383 a, 2026-09-12). The other half of `byok.rs`'s key ring: the ring lets a
//! process READ under every key it holds; this is what moves the rows so the old
//! key can be dropped.
//!
//! What it touches — every column that holds a BYOK blob:
//!   `provider_keys.ciphertext_b64`            AAD `provider-key:<tenant>:<provider>`
//!   `tenant_audit_keys.encrypted_private_key` AAD `audit-key:<tenant>`
//!   `tenant_audit_keys.encrypted_anchor_key`  AAD `anchor-key:<tenant>` (nullable)
//!
//! Per row: read the blob's KEK id from its header (no decrypt); skip it if it is
//! already under the active KEK; otherwise decrypt with the row's AAD, encrypt
//! under the active KEK, and `UPDATE … WHERE <col> = <old blob>` — optimistic, so
//! a row rewritten underneath (a customer rotating their own provider key at the
//! same moment) is left alone and counted, never clobbered. Idempotent and
//! resumable by construction: a second run finds nothing to do; a run killed
//! half-way leaves every row readable (both keys stay in the ring until the
//! operator drops the old one AFTER a run reports `remaining=0`).
//!
//! There is deliberately NO `kek_id` column: the blob carries its own id byte,
//! and a column that must agree with it would be a second source of truth. The
//! distribution an operator wants (`how many rows are still under KEK 0?`) is
//! `--dry-run`'s report, computed from the blobs themselves.
//!
//! Fail-CLOSED on a blob the ring cannot open (`unreadable`): reported by table
//! and tenant, never skipped silently, and the exit code is non-zero.

use anyhow::{Context as _, Result};
use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::byok::ByokMasterKey;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TableReport {
    pub table: &'static str,
    pub rows: u64,
    /// Already sealed under the active KEK.
    pub current: u64,
    /// Rewrapped in this run (dry-run: would be).
    pub rewrapped: u64,
    /// Could not be decrypted under any loaded KEK — or is not a BYOK blob.
    pub unreadable: u64,
    /// The optimistic UPDATE matched no row: rewritten underneath, retried next run.
    pub changed_underneath: u64,
    /// Blobs per KEK id, before this run.
    pub by_kek: std::collections::BTreeMap<u8, u64>,
}

#[derive(Debug, Default, Clone)]
pub struct Report {
    pub active_kek: u8,
    pub dry_run: bool,
    pub tables: Vec<TableReport>,
}

impl Report {
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.tables
            .iter()
            .map(|t| {
                t.unreadable + t.changed_underneath + if self.dry_run { t.rewrapped } else { 0 }
            })
            .sum()
    }
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.tables.iter().map(|t| t.unreadable).sum()
    }
    /// One line per table, the shape the runbook quotes.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "byok-rotate active_kek={} mode={}\n",
            self.active_kek,
            if self.dry_run { "dry-run" } else { "execute" }
        );
        for t in &self.tables {
            let dist = t
                .by_kek
                .iter()
                .map(|(k, n)| format!("kek{k}={n}"))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!(
                "  {}: rows={} current={} {}={} unreadable={} changed_underneath={} [{}]\n",
                t.table,
                t.rows,
                t.current,
                if self.dry_run {
                    "would_rewrap"
                } else {
                    "rewrapped"
                },
                t.rewrapped,
                t.unreadable,
                t.changed_underneath,
                dist
            ));
        }
        out.push_str(&format!(
            "  remaining={} failed={}\n",
            self.remaining(),
            self.failed()
        ));
        out
    }
}

/// One blob-bearing column: how to read every row and how to write one back.
struct Column {
    table: &'static str,
    select: &'static str,
    update: &'static str,
    aad: fn(&Uuid, &str) -> Vec<u8>,
}

const COLUMNS: &[Column] = &[
    Column {
        table: "provider_keys",
        select: "SELECT tenant_id, provider_id, ciphertext_b64 FROM provider_keys ORDER BY tenant_id, provider_id",
        update: "UPDATE provider_keys SET ciphertext_b64 = $3, updated_at = now() \
                 WHERE tenant_id = $1 AND provider_id = $2 AND ciphertext_b64 = $4",
        aad: |t, p| {
            crate::byok::provider_key_aad(&tracelane_shared::TenantId::from_jwt_claim(*t), p)
        },
    },
    Column {
        table: "tenant_audit_keys.encrypted_private_key",
        select: "SELECT tenant_id, '' AS k, encrypted_private_key FROM tenant_audit_keys ORDER BY tenant_id",
        update: "UPDATE tenant_audit_keys SET encrypted_private_key = $3 \
                 WHERE tenant_id = $1 AND $2 = '' AND encrypted_private_key = $4",
        aad: |t, _| crate::byok::audit_key_aad(&tracelane_shared::TenantId::from_jwt_claim(*t)),
    },
    Column {
        table: "tenant_audit_keys.encrypted_anchor_key",
        select: "SELECT tenant_id, '' AS k, encrypted_anchor_key FROM tenant_audit_keys \
                 WHERE encrypted_anchor_key IS NOT NULL ORDER BY tenant_id",
        update: "UPDATE tenant_audit_keys SET encrypted_anchor_key = $3 \
                 WHERE tenant_id = $1 AND $2 = '' AND encrypted_anchor_key = $4",
        aad: |t, _| crate::byok::anchor_key_aad(&tracelane_shared::TenantId::from_jwt_claim(*t)),
    },
];

/// Re-wrap every row not under the active KEK. `dry_run` reads and reports only.
///
/// # Errors
/// A Postgres failure aborts (nothing half-written: each UPDATE is its own
/// statement and the loop stops at the first error). A blob the ring cannot open
/// is NOT an error here — it is counted as `unreadable` and reported, so one bad
/// row does not stop the other rows from moving; `main` exits non-zero on it.
pub async fn rotate(pool: &Pool, ring: &ByokMasterKey, dry_run: bool) -> Result<Report> {
    let active = ring.active_kek();
    let client = pool.get().await.context("pool.get for byok-rotate")?;
    let mut report = Report {
        active_kek: active,
        dry_run,
        tables: Vec::new(),
    };
    for col in COLUMNS {
        let mut t = TableReport {
            table: col.table,
            ..Default::default()
        };
        let rows = client
            .query(col.select, &[])
            .await
            .with_context(|| format!("SELECT {}", col.table))?;
        for row in rows {
            t.rows += 1;
            let tenant: Uuid = row.get(0);
            let key: String = row.get(1);
            let blob: String = row.get(2);
            let Some(kek) = ByokMasterKey::kek_id_of(&blob) else {
                t.unreadable += 1;
                tracing::error!(table = col.table, %tenant, "byok-rotate: not a v2/v3 blob — left as is");
                continue;
            };
            *t.by_kek.entry(kek).or_default() += 1;
            if kek == active {
                t.current += 1;
                continue;
            }
            let aad = (col.aad)(&tenant, &key);
            let plaintext = match ring.decrypt_with_context(&blob, &aad) {
                Ok(p) => p,
                Err(e) => {
                    t.unreadable += 1;
                    tracing::error!(table = col.table, %tenant, kek, error = %e, "byok-rotate: cannot open — left as is");
                    continue;
                }
            };
            if dry_run {
                t.rewrapped += 1;
                continue;
            }
            let fresh = ring.encrypt_with_context(&plaintext, &aad)?;
            let n = client
                .execute(col.update, &[&tenant, &key, &fresh, &blob])
                .await
                .with_context(|| format!("UPDATE {}", col.table))?;
            if n == 1 {
                t.rewrapped += 1;
            } else {
                t.changed_underneath += 1;
            }
        }
        report.tables.push(t);
    }
    Ok(report)
}

/// The `gateway byok-rotate [--dry-run]` entrypoint: builds the ring and the
/// pool from the same environment the serving process uses, runs, prints the
/// report, and exits non-zero if any row could not be moved.
pub async fn main(args: &[String]) -> Result<()> {
    let dry_run = match args {
        [] => false,
        [a] if a == "--dry-run" => true,
        _ => anyhow::bail!("usage: gateway byok-rotate [--dry-run]"),
    };
    let ring = ByokMasterKey::from_env()
        .context("BYOK ring")?
        .context("no BYOK master key configured (TRACELANE_BYOK_MASTER_KEY / _KEYS)")?;
    let pool = crate::db::build_pool().await.context("Postgres pool")?;
    let report = rotate(&pool, &ring, dry_run).await?;
    print!("{}", report.render());
    anyhow::ensure!(
        report.failed() == 0,
        "{} row(s) could not be re-wrapped — see the log lines above",
        report.failed()
    );
    Ok(())
}
