<!-- tracelane:classification: PUBLIC -->
# `crates/policy`

PII redaction for the audit path, plus a **fail-closed policy-engine scaffold**.

What ships today: `pii.rs`, used by the gateway to redact audit payloads before they
enter the hash chain. That is the crate's only live consumer.

- **There is no policy engine.** `engine.rs` has no call sites, returns `Deny` for every
  query, and `cedar-policy` is **not a dependency** of this crate. Per-tenant
  authorization in V1 is Postgres `workspace_entitlements` (deny-overrides-grant).
- A [Cedar](https://www.cedarpolicy.com/)-backed evaluator is the intended design —
  **roadmap, not shipped**. Build state: `GWY-11` (STUB) in the planned-vs-built ledger.
- This is distinct from **entitlements** (feature gating, in
  `workspace_entitlements`) and from operational **kill-switches** — policy
  answers "is this principal allowed this action on this resource", entitlements
  answer "does this plan include this feature".

~14 public items.
