# crates/gateway — local rules

> Loads only when working under `crates/gateway/`. Long form for anything here is
> `docs/TRAPS.md`; this file is the short form you need *at the keyboard*.

## The hot path is ONE function

`chat_completions_handler` — `src/server.rs:882-1712`. **There is no Tower auth layer
and no extractor-based auth.** Every step is inline and sequential in one ~860-line fn:

```
auth :925 → entitlements + rate limit :955 → monthly quota :988
→ predictive/detection (OBSERVE-first) :1036 → audit publish (fail-CLOSED 503) :1076
→ provider resolve + BYOK key :1103 → inline guardrails (fail-CLOSED) :1203
→ untrusted-data wrap → kill-switch + circuit breaker :1319 → dispatch :1341
```

**Adding a route without replicating that sequence ships an unauthenticated endpoint.**
The step-number comments are out of order (`Step 5` appears before `Step 4b`) — trust
the line numbers, not the comments.

Four route groups mount unconditionally (`server.rs:499-503` plus `audit_pubkey` at
`:564-566`); the other ten merges are env-conditional, so a missing env var means a
clean 404, not a broken route.

## `NATS_URL` flips failure semantics at startup

- **Unset ⇒ span publish is DISABLED and ALL spans are dropped** while the gateway
  returns 200s and looks healthy (`server.rs:331-357`). "The gateway is up" is not
  evidence anything is being recorded.
- Audit is async via JetStream and **fail-CLOSED** (`503 audit_unavailable`). But if
  NATS is unset, connect fails, `ensure_audit_stream` fails, or the `kill.audit.async`
  flag is true, `publish()` silently falls back to the **synchronous** `append()`,
  which is **fail-OPEN** — it swallows its own error and the request proceeds
  (`audit.rs:497-508`).

**Same code path, opposite semantics, decided at startup and flippable at runtime.** A
test asserting 503-on-audit-failure only passes when JetStream is wired.

## BYOK: routed ≠ usable (two allowlists)

`ProviderRegistry::provider_id_for_model` (routing) and `is_known_provider`
(`byok_api/provider_keys_api.rs:226-273`, key upload) are **separate lists**. They
drifted before — B-145: four providers were routable but 400'd on key upload, so a
customer could not store a key for them at all.

Adding a provider means touching **three** places in lockstep — `provider_id_for_model`,
`env_var_for_provider_id`, `dispatch_to_provider` — **plus** `is_known_provider`.
Missing one produces credential misrouting (B-127) or an unstorable key (B-145).

Kept in sync by `scripts/ci/check-byok-provider-coverage.py` and
`check-provider-count.py` — **note both run only in `verify-all.sh`, not in any CI
workflow.** Currently 35 routable = 7 native + 28 OpenAI-compatible.

The model→provider map **fails closed** (`providers/mod.rs:709-712`): no default
provider, because defaulting would ship the wrong tenant's BYOK credential.

## Other things that bite here

- **`lib.rs` exposes only `rate_limiter` + `circuit_breaker`.** Everything else lives in
  the bin target. Use `cargo test -p gateway --bin gateway` to target the ~735 tests.
- **`main.rs` and `lib.rs` both carry crate-wide `#![allow(dead_code, unused_imports, …)]`**,
  so `clippy -D warnings` **cannot** catch an unwired module here.
- **`TRACELANE_APIKEY_PEPPER` is required in release builds** when Postgres is
  configured; debug installs a `"00"*32` test pepper behind a `warn!`. A key minted
  under one pepper never verifies under the other.
- **Entitlement resolution fails OPEN** to a `last_known` grant — but a **cold** process
  during a Neon outage silently downgrades everyone to free-tier limits.
- **SSRF:** `validate_url` + `safe_client_builder` before any outbound request to an
  operator- **or** customer-supplied URL. The prompt-guard sidecar's loopback carve-out
  is **caller-local** (`predictive/prompt_guard.rs:124,195`) and must never migrate into
  `ssrf_guard` — a containment test enforces that.
