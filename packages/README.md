<!-- tracelane:classification: PUBLIC -->
# `packages/` — publishable libraries

Language SDKs, the CLI, the shared UI system, and the audit-ledger reference
verifiers. These are the surfaces customers install; they ship publicly (Apache
2.0) via OIDC Trusted Publishing. See [`../docs/guides/architecture.md`](../docs/guides/architecture.md) for system context.

| Package | Role |
|---|---|
| [`sdk-python`](sdk-python/) | Python instrumentation SDK (OTel-GenAI spans). |
| [`sdk-typescript`](sdk-typescript/) | TypeScript SDK — provider + MCP instrumentation (`@tracelanedev/sdk`). |
| [`cli`](cli/) | `tlane` CLI (migrate/import, audit verify). |
| [`ui`](ui/) | `@tracelanedev/ui` — the "Tinted Slate + Lava" design system (tokens + components; ADR-053, which supersedes the ADR-045 Neon palette on tokens). Surfaces read tokens from here, never hardcode hex. |
| [`verifier-rust`](verifier-rust/) | Reference audit-ledger verifier (Rust). |
| [`verifier-typescript`](verifier-typescript/) | Reference audit-ledger verifier (TS). |
| [`verifier-python`](verifier-python/) | Reference audit-ledger verifier (Python). |

The three verifiers are **identical by construction** on the v2.1 canonical
format (ADR-050): `payload` is the verbatim stored canonical string, SHA-256'd
byte-for-byte, never re-derived — so no cross-language numeric-canonicalization
drift is possible. Conformance vectors: `../evals/audit-ledger/`.
