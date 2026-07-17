//! Library re-exports for benchmarks and external integration tests.
//!
//! The gateway is primarily a binary (`src/main.rs`). This `lib.rs` exists
//! solely to expose the modules that criterion benches and out-of-process
//! integration tests need to import — currently just `rate_limiter`, where
//! the ADR-020 hot-path budget (<500ns p99) is enforced via
//! `benches/rate_limiter.rs`.
//!
//! Dual-compile note: `main.rs` keeps its own `mod rate_limiter;`, and this
//! `lib.rs` also declares `pub mod rate_limiter;`. The source file is
//! compiled twice (once into the binary, once into the library). This is
//! intentional and matches the canonical Rust bin+lib hybrid pattern —
//! the bench needs library access without forcing `main.rs` to re-route
//! every internal call through the library path.

#![allow(
    dead_code,
    unused_imports,
    clippy::needless_return,
    clippy::collapsible_match,
    clippy::collapsible_if,
    clippy::manual_is_multiple_of
)]

pub mod circuit_breaker;
pub mod rate_limiter;
