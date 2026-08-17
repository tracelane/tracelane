//! Shared types used by all Tracelane crates.
//!
//! - `model` — universal chat API types (ChatRequest, ChatResponse, Message, Tool)
//! - `span` — TracelaneSpan with OTel + OpenInference semantic convention attributes
//! - `tenant` — TenantId opaque wrapper (only constructible from a JWT claim)
//! - `self_host` — single-tenant self-host mode config + multi-tenant hard-fail
//!   guard, shared by the gateway (auth) and ingest (SPIRE-less span path). ADR-067.
//! - `redact` — credential / API-key scrubbing for the tracing subscriber.
//!   Used by both gateway and ingest so log output from either binary is
//!   protected by the same byte-scan pattern set (A10).
//! - `otlp` — the OTLP protobuf decoder and the ADR-029 payload caps. Here
//!   rather than in `ingest` because `GWY-41` gave OTLP a SECOND entry point
//!   (the gateway's authenticated `POST /v1/traces`) and two entry points must
//!   not mean two decoders. `ingest` re-exports both under their old paths.
//! - `aft` — the AFT failure-signature id shape (ADR-056 H1), needed by the
//!   decoder above and by ingest's federation writer.

pub mod aft;
pub mod api_scope;
pub mod degradation;
pub mod listen_dsn;
pub mod model;
pub mod otlp;
pub mod redact;
pub mod self_host;
pub mod span;
pub mod tenant;

pub use model::{
    ChatRequest, ChatResponse, Choice, ContentPart, ImageUrl, Message, MessageContent,
    RequestMetadata, Role, Tool, ToolCall, Usage,
};
pub use span::{Intervention, SpanAttributes, SpanStatus, SpanStatusCode, TracelaneSpan};
pub use tenant::TenantId;
