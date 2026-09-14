//! Inline guardrails — the V1 request/response enforcement substrate.
//!
//! This module is the canonical implementation of the guardrail spec
//! (v2). It owns the rich evaluation context every rail reads
//! ([`context::GuardrailContext`]), the outcome vocabulary the dispatcher and
//! rails speak ([`outcome`]), the tool-capability registry ([`capability`]),
//! the concurrent dispatcher, the tamper-evident verdict recorder, entitlement
//! gating, and per-rail metrics.
//!
//! It is **additive** to the older `crate::predictive` layer (see
//! `.md` 2026-06-19 architecture decision): the spec's
//! `RailOutcome` model — `block | redact | warn | allow | not_applicable |
//! fail_open` with score / reason_code / latency — is richer than the
//! predictive layer's `Decision`, so guardrails get a purpose-built substrate
//! rather than forcing 14 predictors (most outside V1 scope) onto it.
//!
//! Invariants enforced here:
//! - Security rails fail **closed** (block on error/timeout); quality rails
//!   fail **open-loud** (proceed, but a `fail_open` verdict is recorded — a
//!   silent skip is a P0 defect).
//! - `tenant_id` is always the resolved internal `tenants.id` UUID; a raw
//!   WorkOS `org_id` never reaches a store read (§0; P0.2).
//! - Verdict `details` never carry raw secrets, full PII, or full prompt text
//!   (§2.5; redaction + CI grep).

pub mod capability;
pub mod context;
pub mod dispatcher;
pub mod engine;
pub mod metrics;
pub mod outcome;
pub mod rail;
pub mod rails;
pub mod recorder;
pub mod registry_loader;
pub mod streaming;
pub mod tool_observer;
pub mod tool_pins_api;
pub mod verdict;

// B-390 (2026-09-12): this re-export block used to name every public item in
// every submodule, most of which nothing ever consumed via `guardrail::X` —
// callers that need e.g. `outcome::FailMode` reach it through the submodule
// path directly (`crate::guardrail::outcome::FailMode`), not through here.
// Pruned to exactly what `crate::guardrail::X` (this top-level path) is
// actually used for elsewhere in the crate. `CapabilitySet` is used only by
// a test in `context.rs`, hence gated rather than deleted.
pub use capability::CapabilityRegistry;
#[cfg(test)]
pub use capability::CapabilitySet;
pub use context::{ResponseInputs, SessionState};
pub use engine::{GuardrailEngine, RequestInputs};
pub use outcome::{Decision, Outcome};
pub use registry_loader::{RegistryLoader, pg_registry_resolver};
pub use streaming::{GuardStep, ResponseGuard};
