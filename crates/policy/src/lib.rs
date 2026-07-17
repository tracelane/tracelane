//! Cedar policy evaluation for Tracelane.
//!
//! Cedar is AWS's open-source policy language. Tracelane uses it to express
//! per-tenant access control policies for: gateway routing, data export,
//! retention overrides, and predictive layer configuration.
//!
//! Policies are stored in Postgres and evaluated inline on each request.
//! The `cedar-policy` crate is the authoritative evaluator.
//!
//! This stub evaluates all policies as `Allow`. Full implementation (Week 5).

pub mod engine;
pub mod pii;

pub use engine::{PolicyDecision, PolicyEngine};
