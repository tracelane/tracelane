//! OTLP wire handling — the decoder and the ADR-029 payload caps.
//!
//! **Why this lives in `shared` and not in `ingest`.** Until `GWY-41` there was
//! exactly one OTLP entry point (ingest's mTLS receiver) so the decoder lived
//! beside it. `GWY-41` adds a second one — the gateway's authenticated
//! `POST /v1/traces` (B-227: without it a Tracelane Cloud customer cannot
//! produce a multi-span trace at all). Two entry points must not mean two
//! decoders: a fork is a second thing to drift, and the thing that would drift
//! is the mapping from an untrusted wire format onto the canonical
//! [`crate::TracelaneSpan`].
//!
//! `TracelaneSpan` already lives here, so the code that produces one from OTLP
//! bytes belongs next to it. `ingest` re-exports both modules under their old
//! paths (`crate::otlp_decode`, `crate::limits`), so every ingest call site and
//! bench compiles unchanged.
//!
//! - [`decode`] — `ExportTraceServiceRequest` → `Vec<TracelaneSpan>`, including
//!   the tenant-resolution rule that makes a body-supplied `tenant_id`
//!   unusable in release builds.
//! - [`limits`] — ADR-029 size caps, the reject taxonomy and its counters.

pub mod decode;
pub mod limits;
