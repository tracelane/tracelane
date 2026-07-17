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

pub mod model;
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
