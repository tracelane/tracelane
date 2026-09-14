//! Ingest service configuration loaded from environment variables.
//!
//! All values have safe defaults for local development.
//! Production values are injected via Kubernetes secrets / Hetzner env.

use anyhow::{Context as _, Result};

pub struct IngestConfig {
    /// Port for the OTLP HTTP receiver (default: 4318).
    pub otlp_port: u16,
    /// NATS JetStream URL (default: nats://localhost:4222).
    pub nats_url: String,
    /// ClickHouse HTTP endpoint (default: http://localhost:8123).
    pub clickhouse_url: String,
    /// ClickHouse database name (default: tracelane).
    pub clickhouse_db: String,
    /// ClickHouse username (default: default).
    pub clickhouse_user: String,
    /// ClickHouse password.
    pub clickhouse_password: String,
    /// Max spans per ClickHouse insert batch (default: 2000).
    pub batch_size: usize,
    /// Max ms to hold a batch before flushing even if not full (default: 200).
    pub batch_timeout_ms: u64,
    /// Baseline tail-sampling keep rate (0..=100) for traces with no error or
    /// intervention; error/intervention traces are always kept (PP-O2). The
    /// ClickHouse writer drops the rest at this rate. **Default 100 (V1:
    /// full-fidelity capture)** — a flight recorder that silently drops clean
    /// spans contradicts the product positioning (#81). Sampling is opt-in cost
    /// control: set below 100 to drop a fraction of clean traces. Env:
    /// `TRACELANE_TAIL_SAMPLE_RATE_PCT` (values >100 are clamped to 100).
    pub tail_sample_rate_pct: u8,
    /// Path to the SPIRE Workload API Unix socket. When set, the OTLP
    /// receiver enforces SPIFFE mTLS (INGEST-002). When unset, the
    /// receiver runs in plaintext (dev only — never in prod).
    pub spire_socket: Option<String>,
    /// SPIFFE trust domain accepted by ingest workers (default: `tracelane.dev`).
    /// Plays the role of the `trust_domain` constant in `auth.rs`; both must agree.
    pub spire_trust_domain: String,
    /// Per-trace span ceiling (ADR-048 D4.3): max spans retained per single trace
    /// before further spans are intentionally (counted, not silent) dropped.
    /// Bounds the fat-agent-trace 1000× cost class on all tiers incl forced-full.
    /// `0` disables. Env: `TRACELANE_MAX_SPANS_PER_TRACE` (default 10000).
    pub max_spans_per_trace: u32,
    /// Per-trace byte ceiling (estimated total span bytes per single trace).
    /// `0` disables. Env: `TRACELANE_MAX_BYTES_PER_TRACE` (default 64 MiB).
    pub max_bytes_per_trace: u64,
    // `default_ingest_quota` (ADR-048 D4.2 default monthly span quota) and
    // `fault_quota` (review P1-1's finite fault-path cap) are BOTH GONE —
    // ADR-076 §0.4 retired the per-tenant ingest span quota outright ("ingest
    // is NEVER blocked by billing state, on any tier"). `TRACELANE_INGEST_
    // DEFAULT_QUOTA` / `TRACELANE_FAULT_QUOTA` are no longer read; an operator
    // who still sets either now gets a silent no-op, same as any other
    // retired env var in this tree.
}

impl IngestConfig {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    /// Returns `Err` if `TRACELANE_INGEST_PORT` is set to a non-numeric value.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            otlp_port: std::env::var("TRACELANE_OTLP_PORT")
                .unwrap_or_else(|_| "4318".into())
                .parse()
                .context("TRACELANE_OTLP_PORT must be a valid port number")?,
            nats_url: std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".into()),
            clickhouse_url: std::env::var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://localhost:8123".into()),
            clickhouse_db: std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "tracelane".into()),
            clickhouse_user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()),
            clickhouse_password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default(),
            batch_size: std::env::var("INGEST_BATCH_SIZE")
                .unwrap_or_else(|_| "2000".into())
                .parse()
                .context("INGEST_BATCH_SIZE must be a number")?,
            batch_timeout_ms: std::env::var("INGEST_BATCH_TIMEOUT_MS")
                .unwrap_or_else(|_| "200".into())
                .parse()
                .context("INGEST_BATCH_TIMEOUT_MS must be a number")?,
            tail_sample_rate_pct: std::env::var("TRACELANE_TAIL_SAMPLE_RATE_PCT")
                .unwrap_or_else(|_| "100".into())
                .parse()
                .context("TRACELANE_TAIL_SAMPLE_RATE_PCT must be an integer 0..=100")?,
            spire_socket: std::env::var("TRACELANE_SPIRE_SOCKET").ok(),
            spire_trust_domain: std::env::var("TRACELANE_TRUST_DOMAIN")
                .unwrap_or_else(|_| "tracelane.dev".into()),
            max_spans_per_trace: std::env::var("TRACELANE_MAX_SPANS_PER_TRACE")
                .map(|v| v.parse())
                .unwrap_or(Ok(crate::per_trace_ceiling::DEFAULT_MAX_SPANS_PER_TRACE))
                .context("TRACELANE_MAX_SPANS_PER_TRACE must be a u32")?,
            max_bytes_per_trace: std::env::var("TRACELANE_MAX_BYTES_PER_TRACE")
                .map(|v| v.parse())
                .unwrap_or(Ok(crate::per_trace_ceiling::DEFAULT_MAX_BYTES_PER_TRACE))
                .context("TRACELANE_MAX_BYTES_PER_TRACE must be a u64")?,
        })
    }
}
