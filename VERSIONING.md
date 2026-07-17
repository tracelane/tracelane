# Versioning & Stability Policy

> Status: **v1, 2026-07-17.** This is the stability contract for everything Tracelane
> publishes. It exists because we publish packages to public registries
> (crates.io / npm / PyPI) and you should not depend on a `0.x` package without knowing
> what "0.x" means here.

## TL;DR

- We follow **[Semantic Versioning 2.0.0](https://semver.org/)**.
- Everything is currently **pre-1.0 (`0.x`)** — see [Pre-1.0 posture](#pre-10-posture).
- The **gateway HTTP API is versioned in the path (`/v1/…`)** and is the surface we treat
  most conservatively; see [API stability](#api-stability-v1).
- Breaking changes are announced in `CHANGELOG.md` (Keep a Changelog format) and, once we
  reach 1.0, carry a deprecation window.

## What SemVer covers (the versioned surfaces)

Each has its own version and its own SemVer contract:

| Surface | Where | Version today | SemVer applies to |
|---|---|---|---|
| Gateway HTTP API | `https://gateway.tracelane.dev/v1/…` | `v1` (path) | request/response shape of documented `/v1` endpoints |
| Python SDK | `tracelane` (PyPI) | `0.1.0` | public `import tracelane` surface (`init`, `instrument_*`) |
| TypeScript SDK | `@tracelanedev/sdk` (npm) | `0.1.0` | public exports (`instrument*`, config types) |
| CLI | `@tracelanedev/cli` (npm) | `0.2.0` | command names, flags, exit codes |
| Audit wire format / verifier | `packages/verifier-*`, `spec/` | verifier `0.2.0` | the audit record format a third party verifies |
| Rust crates | `crates/*` | `0.1.0` | not published for external use in V1 (internal) |
| Specs (AFT-1, OpenAgentTrace) | `spec/` | AFT-1 `v0.3` draft, OAT `v0.1` draft | see [Spec versioning](#spec-versioning) |

**These version independently.** An SDK minor bump does not imply a gateway change, and vice
versa — see [SDK ↔ gateway compatibility](#sdk--gateway-compatibility).

## API stability (`/v1`)

- The **major version lives in the URL path** (`/v1`). Within `v1`, we make only
  backward-compatible changes: adding an endpoint, adding an optional request field, or adding
  a response field. Existing fields do not change type or disappear within a major.
- A **breaking** change to the HTTP contract ships as **`/v2`**, run in parallel with `/v1`
  for a deprecation window (see [Deprecation](#deprecation)); `/v1` is not removed the day
  `/v2` lands.
- Clients should **ignore unknown response fields** so an additive change never breaks them.
- **Not covered by the `/v1` contract:** internal error *message strings* (the machine-readable
  `error` code is stable; the human `message` is not), undocumented fields, and endpoints
  explicitly marked *roadmap/V1.1* in the docs.

## Pre-1.0 posture

Everything is `0.x` today, and under SemVer `0.x` allows breaking changes in a **minor** bump.
Our pre-1.0 promise is narrower than "anything goes":

- The **gateway `/v1` HTTP API is treated as stable already** — it is the surface most people
  integrate against, and we will not break it in a `0.x` gateway bump. (The path version, not
  the package version, is the contract.)
- **SDKs and the CLI may make breaking changes in a `0.minor` bump** while pre-1.0, but each is
  announced in `CHANGELOG.md` and we avoid it without cause.
- **1.0 is cut** when the SDK/CLI surfaces have been stable across at least one minor cycle with
  no forced breaks; at that point full SemVer (breaking = major only) applies to them too.

## SDK ↔ gateway compatibility

- SDKs talk to the gateway over the **`/v1` HTTP API only** — they do not depend on a specific
  gateway *package* version. Any `0.x` SDK works against any gateway serving `/v1`.
- The compatibility contract is therefore **"SDK vN ⟷ gateway `/v1`"**, not a version-pair
  matrix. When `/v2` is introduced, SDKs will declare which API major they target.
- The **audit verifier** is the one place a format version matters: a verifier validates a
  declared audit-record format version and refuses an unknown one rather than guessing (fail
  closed). The format version travels in the record, not in the package version.

## Spec versioning

`spec/aft-1` (Agent Failure Taxonomy) and `spec/openagenttrace` are **published as CC0 drafts**
(`v0.3`, `v0.1`). Draft specs may change between draft versions; each carries a change table.
They reach a stability commitment (no breaking changes without a major) at **v1.0**, not before.
Downstream implementers should pin the draft version they built against.

## Deprecation

Pre-1.0, deprecation is **announcement-based**: a deprecated field/endpoint/flag is called out
in `CHANGELOG.md` under a `Deprecated` heading with the replacement and the earliest version it
may be removed. Post-1.0, deprecations carry a **minimum one-minor-version window** (a thing
deprecated in `x.n` is not removed before `x.(n+2)` or the next major, whichever is sooner), and
HTTP responses for a deprecated `/v1` route will carry a `Deprecation` / `Sunset` header.

> A fuller standalone DEPRECATION policy (per-surface sunset timelines, header semantics) is a
> post-launch follow-up; this section is the pre-publish minimum.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/) with
`Added / Changed / Deprecated / Removed / Fixed / Security` sections. Every breaking change,
deprecation, and security fix lands there before or with the release that carries it.
