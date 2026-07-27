//! Library re-exports for benchmarks and external integration tests.
//!
//! The ingest binary lives at `src/main.rs`. This `lib.rs` exists solely
//! to expose modules that criterion benches and out-of-process integration
//! tests need to import:
//!   * `limits` — ADR-029 hot-path budget: pre-decode reject in <1 µs p50
//!     for a 10 MiB payload.
//!   * `cardinality` — ADR-030 hot-path budget: `observe_and_classify` in
//!     <200 ns p99 over 1M calls.
//!
//! Dual-compile note: `main.rs` keeps its own `mod limits;` /
//! `mod cardinality;`, and this `lib.rs` also declares `pub mod` for
//! each. The source files are compiled twice (once into the binary,
//! once into the library). Intentional — matches the canonical Rust
//! bin+lib hybrid pattern used by `crates/gateway` and required by
//! criterion's bench harness target.

#![allow(
    dead_code,
    unused_imports,
    clippy::needless_return,
    clippy::collapsible_match,
    clippy::collapsible_if
)]

pub mod cardinality;
pub mod limits;
// Dual-compiled with `main.rs`'s `mod tail_sampler;` (same pattern as the two
// above) so the PP-O2 sampler hot path is reachable from `benches/sampler.rs`.
pub mod tail_sampler;
