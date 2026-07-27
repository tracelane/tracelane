# `crates/shared`

Shared types and helpers used by **all** Tracelane Rust crates (gateway,
ingest, policy, mcp-rs). Keeping them here means the two binaries redact logs
and model spans with exactly the same code.

## Modules
- **`model`** — universal chat API types (`ChatRequest`, `ChatResponse`, `Message`, `Tool`) that every provider adapter maps to/from.
- **`span`** — `TracelaneSpan` with OTel-GenAI + OpenInference semantic-convention attributes (the wire format, ADR-001).
- **`tenant`** — `TenantId`, an opaque wrapper **only constructible from a validated JWT claim** (`from_jwt_claim`) or a verified SPIFFE SVID — the structural enforcement of tenant isolation (never from a request body).
- **`redact`** — credential / API-key scrubbing for the `tracing` subscriber (`sk-`, `org-`, `AKIA`, `AIza`, Stripe/Polar, bearer, JWT shapes). Defense in depth — the first line is not logging secrets at all.

~28 public items. No hot-path allocation concerns here; this crate is types +
pure functions. See `../../docs/REPO_MAP.md` and `../../.claude/rules/security.md`.
