//! Tenant identity — opaque `TenantId` type.
//!
//! `TenantId` can only be constructed via one of three explicit trust
//! boundaries: a validated JWT claim (gateway path), a verified SPIFFE
//! X.509-SVID (ingest mTLS path), or the single operator-configured tenant of a
//! self-host deployment (`from_self_host_config`, reachable only from the
//! ADR-067 single-tenant mode, which hard-fails on any multi-tenant signal). All
//! constructors are explicit so an audit grep for `TenantId::from_` enumerates
//! every trust boundary.
//! This invariant is the primary defence against cross-tenant data leaks.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Opaque wrapper ensuring tenant IDs always come from cryptographically
/// attested sources (JWT claim or SPIFFE SVID), never from request bodies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Construct from a validated JWT claim. Caller MUST have verified the JWT
    /// signature against the WorkOS JWKS before extracting the claim value.
    pub fn from_jwt_claim(raw: Uuid) -> Self {
        Self(raw)
    }

    /// Construct from a verified SPIFFE X.509-SVID path component.
    /// Caller MUST have verified the SVID chain against the SPIRE trust bundle
    /// AND validated the SPIFFE ID's trust domain before extracting the tenant
    /// UUID from the path. See `ingest::auth::verify_spiffe_svid`.
    pub fn from_spiffe_svid(raw: Uuid) -> Self {
        Self(raw)
    }

    /// Construct from the operator-configured single-tenant self-host id
    /// (`TRACELANE_SINGLE_TENANT_ID`). This is a trust boundary DISTINCT from
    /// the JWT/SVID paths: it is only reachable when the process booted in
    /// single-tenant self-host mode, which `self_host::resolve` hard-fails to
    /// enter if ANY multi-tenant/hosted signal is present. Because there is
    /// exactly one tenant in that deployment, no request can escalate to a
    /// second tenant — the multi-tenant `tenant_id`-spoof threat SPIFFE guards
    /// against cannot occur. Never call this from the hosted control plane.
    pub fn from_self_host_config(raw: Uuid) -> Self {
        Self(raw)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for TenantId {
    /// Display format is the canonical hyphenated lowercase UUID
    /// (e.g. `00000000-0000-0000-0000-000000000001`).
    ///
    /// This format is **stable** — any storage row, log line, span
    /// attribute, or audit ledger field that records a TenantId via
    /// `Display` (or `to_string()`) relies on this exact representation.
    /// The contract is locked by
    /// `tests::display_format_matches_canonical_hyphenated_uuid`.
    ///
    /// If you need a different format, add a new explicit accessor;
    /// **do not** change this impl. Notable callers that would silently
    /// diverge from `audit_format::row_hash_v2` (which hashes
    /// `as_uuid().as_bytes()`) include `audit_log` row writes and
    /// ClickHouse `WHERE tenant_id = ?` filters
    /// (`audit.rs::backfill_rekor_entry_id`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format_matches_canonical_hyphenated_uuid() {
        // Opus-rereview Phase-3 MED-3: ClickHouse row writes store
        // tenant_id via `Display`, while the audit row hash binds
        // `as_uuid().as_bytes()`. If `Display` ever changes (dropping
        // hyphens, uppercasing, etc.) the two diverge silently — a
        // verifier rebuilding the chain from ClickHouse rows would see
        // mismatches across the board with no explicit error. Lock the
        // format now.
        let tid = TenantId::from_jwt_claim(
            Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
        );
        assert_eq!(tid.to_string(), "11111111-2222-3333-4444-555555555555");
        // Lowercase, hyphenated, exactly 36 chars including hyphens.
        let s = tid.to_string();
        assert_eq!(s.len(), 36);
        assert_eq!(s, s.to_ascii_lowercase());
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn display_round_trips_through_parse() {
        // Defence in depth — ensure the parsed-back UUID is bit-equal.
        let original = Uuid::parse_str("aabbccdd-eeff-1234-5678-90abcdef0123").unwrap();
        let tid = TenantId::from_jwt_claim(original);
        let s = tid.to_string();
        let reparsed = Uuid::parse_str(&s).unwrap();
        assert_eq!(*tid.as_uuid(), reparsed);
    }
}
