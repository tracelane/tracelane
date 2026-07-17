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
pub mod verdict;

pub use capability::{CapabilityRegistry, CapabilitySet, RegistryPosture, ToolCapability, ToolDef};
pub use context::{
    GuardrailContext, IncomingToolResult, ProposedToolCall, Provenance, ResponseBuffer,
    ResponseInputs, RetrievedChunk, SessionState, TaintSource, TaintState,
};
pub use dispatcher::{Dispatcher, RailRecord, SideOutcome};
pub use engine::{GuardrailEngine, RequestEvaluation, RequestInputs};
pub use metrics::{GuardrailMetrics, record_side_outcome};
pub use outcome::{Decision, FailMode, Outcome, RailError, RailOutcome, Side, Sides, reason_codes};
pub use rail::{GuardrailFeature, Rail, RailFuture, RailGate};
pub use recorder::GuardrailRecorder;
pub use registry_loader::{RegistryLoader, pg_registry_resolver};
pub use streaming::{GuardStep, ResponseGuard, STREAM_HOLDBACK_CHARS};
pub use verdict::{GuardrailVerdict, RailVerdict, VERDICT_SCHEMA};
