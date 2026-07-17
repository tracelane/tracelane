//! Stub — real provider smoke tests live as a unit-test module under
//! `crates/gateway/src/providers/smoke_tests.rs`.
//!
//! Integration tests in `tests/` would require the gateway crate to expose
//! a public library API; we keep gateway as bin-only for now and run
//! provider smoke tests as crate-internal unit tests instead.
