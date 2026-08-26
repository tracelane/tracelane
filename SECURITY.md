<!-- tracelane:classification: PUBLIC -->
# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` branch | ✅ Active |
| Tagged releases | ✅ Last 2 minor versions |
| Older releases | ❌ No security patches |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **security@tracelane.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact
- Any proof-of-concept (privately, please)

We will acknowledge receipt within **72 hours** and provide a remediation
timeline within 7 days; we target a **30-day patch** for critical
vulnerabilities. We follow responsible disclosure: 90-day embargo before public
disclosure, coordinated with reporter.

## Security guarantees

### What Tracelane guarantees

- **BYOK only:** Provider API keys are envelope-encrypted at rest with
  **AES-256-GCM via `ring`**. Each ciphertext is bound to its
  `(tenant_id, provider_id)` via AAD — a row swap across tenants
  fails GCM authentication. Master key (32 bytes) is loaded from
  `TRACELANE_BYOK_MASTER_KEY` at startup; production deployments
  source the env var from a KMS (AWS KMS / GCP KMS / Vault) at
  process launch. Keys never appear in logs, spans, or errors — the
  tracing redaction filter scrubs OpenAI `sk-`, Anthropic `sk-ant-`,
  Google `AIza`, Stripe / Polar `sk_live_/whsec_/rk_`, AWS `AKIA`,
  bare `Bearer`, and JWT-shaped tokens.
- **Tenant isolation:** Every ClickHouse query includes
  `WHERE tenant_id = ?`. `tenant_id` is extracted from a validated
  JWT claim or a verified SPIFFE X.509-SVID only — never from the
  request body. The `tracelane_shared::TenantId` type can only be
  constructed via `from_jwt_claim` or `from_spiffe_svid`, making
  body-supplied values a compile-time impossibility.
- **JWT validation:** Algorithm allowlist
  `[RS256, RS384, RS512, ES256, EdDSA]`. HMAC family hard-denied
  (closes the alg-confusion attack class). `WORKOS_AUDIENCE`
  mandatory in release builds.
- **Webhook integrity:** Polar.sh (payments) and WorkOS (auth)
  webhook handlers verify HMAC signatures in constant time, reject
  events older than 5 minutes, and dedupe on `(source, event_id)`
  via Postgres before any side effect runs. Replay cannot re-fire
  `subscription.deleted` to downgrade a paying tenant.
- **SSRF:** All outbound HTTP from gateway providers passes through
  `validate_url`. Blocked ranges: RFC 1918, 100.64/10, 169.254/16
  (AWS/GCP IMDS), 168.63.129.16 (Azure IMDS), 127/8, ::1, ::,
  fc00::/7, 240/4, 2001:db8::/32, and **IPv4-mapped IPv6**
  (recurses through `to_ipv4_mapped`). HTTP redirects are
  **disabled** on the SSRF-hardened client —
  per-hop sync validation could not catch domain-resolves-to-
  private-IP TOCTOU attacks, so every caller now talks to a fixed
  endpoint. Future callers wanting redirects must re-validate each
  `Location:` via the async `validate_url`.
- **mTLS for ingest:** SPIFFE/SPIRE-issued X.509-SVIDs with 1-hour
  rotation, hot-reloaded via the SPIRE Workload API into an
  `arc-swap`-installed trust bundle (per-connection cache; new
  handshakes pick up rotated bundles, in-flight requests complete
  on old bundles). TLS 1.3 minimum; client auth mandatory; rustls
  `ClientCertVerifier` validates the chain against the SPIRE bundle.
  Application-layer SVID checks (BasicConstraints::cA = false,
  KeyUsage::digital_signature, ASCII-case-insensitive trust domain,
  path shape `/tenant/<uuid>/ingest-worker`) live in
  `crates/ingest/src/auth.rs`.
- **Tamper-evident audit ledger** (`$999/mo` SKU): per-tenant SHA-256
  hash chain. Row hash uses length-prefixed, domain-separated framing
  (`tracelane-audit-row-v2\0`) — field-boundary attacks via
  attacker-controlled `actor` cannot collide rows. Merkle tree per
  RFC 6962 §2.1 (leaf prefix `0x00`, node prefix `0x01`, raw bytes;
  lone-odd-leaf promoted, not duplicated — closes second-preimage).
  Every 100 events the Merkle root is signed with a per-tenant
  Ed25519 key (envelope-encrypted via BYOK; Enterprise tier) or the
  global key (lower tiers), and submitted to Sigstore Rekor v2 as a
  `hashedrekord`. Chain state persists across restarts via the
  `audit_chain_state` Postgres table with monotonic UPSERT
  semantics.
- **Prompt injection awareness:** User-supplied span content is
  wrapped in `<UNTRUSTED_USER_DATA>` sentinel before any agent reads
  it. PII redaction (`crates/policy/src/pii.rs`) runs over audit
  payloads before they enter the chain — secrets that leak past a
  caller cannot reach ClickHouse or Rekor anchor batches.
- **Supply chain:** Trusted Publishing OIDC only (no long-lived
  tokens). Sigstore Cosign keyless signatures on all releases.
  CycloneDX SBOM attached. Build provenance is attested via GitHub
  `attest-build-provenance`, alongside the Cosign bundle. **We do not
  claim a verified SLSA Level 3 attestation** — the repository runs
  `slsa-github-generator` but its `final` job currently fails even on
  successful releases. `.pth` file scanner in CI.
- **No admin endpoints:** Tracelane has no `/config/update`-style
  endpoints. No `eval` or import-by-string of untrusted
  configuration.
- **Dependency hygiene:** `cargo audit` and `pnpm audit` run on
  every PR. No new dependencies from publishers under 6 months
  tenure or under 100 stars without security-reviewer approval.

### Known gaps vs the published guarantees

Re-verified against the code on 2026-08-06. Three items previously listed
here had already been closed and are removed below; what remains is what is
genuinely still open.

- **No qualified timestamping**: audit-ledger anchor timestamps come from
  the gateway host's `Utc::now()`. They are not countersigned by a
  qualified trusted timestamping authority, and Tracelane makes no
  eIDAS qualified-timestamp claim.

**Closed since the 2026-05-23 revision of this list** (each verified against the
code on 2026-08-06, not against a changelog):

- **Customer-side audit verifier** — now verifies both halves.
  `packages/verifier-rust/src/lib.rs` validates the Ed25519 signature against
  the recomputed Merkle root using the trusted tenant public key (`:71`,
  `:135-139`, `:220-228`), and validates the Rekor inclusion proof per
  RFC 6962 §2.1.1 plus the C2SP signed-note checkpoint (`:570-575`,
  `:618-649`, `:676-724`, `:1176-1217`). An inclusion-proof root that
  disagrees with the verified checkpoint root is rejected.
- **API-key storage** — keys are stored as a peppered HMAC-SHA256 lookup index
  plus an Argon2id PHC string with a per-row salt
  (`crates/gateway/src/db/api_keys.rs:204-209`, `:417-496`). There is no
  bare-SHA-256 fallback: a row whose Argon2id PHC is absent or fails is
  rejected (`:480-486`). Note the auth-result cache (`:158-169`, 900s TTL):
  Argon2id runs on the cold path, and a warm-cache hit re-authenticates on the
  peppered digest alone. At rest, a DB dump yields peppered + Argon2id-hashed
  material, not confirmable digests.
- **JWKS fetch** — `WORKOS_JWKS_URL` passes a host allowlist (`workos.com`
  exact plus `.workos.com` suffix) and the SSRF guard before any request is
  sent (`crates/gateway/src/auth/jwks.rs:202-203`, `:212-242`, `:267`), and the
  client is built by `ssrf_guard::safe_client_builder()` with rustls
  (`crates/gateway/src/ssrf_guard.rs:194-214`). **This is a host allowlist and
  a hardened TLS client — it is not certificate pinning**; there is no pinned
  root or custom certificate verifier.

### Deliberate attack-surface reductions

Each item below is a capability Tracelane deliberately does **not** ship, or a
gate that fails closed. Some restate a guarantee above; they are collected here
because the property is the *absence*, which is easy to miss in a feature list.

- **No admin configuration endpoint.** There is no `/config/update`-style route —
  runtime configuration cannot be mutated over HTTP by any caller.
- **No `eval`, no string-templated policy on the request path.** Per-tenant
  authorization is resolved in Postgres `workspace_entitlements`
  (deny-overrides-grant); nothing on the request path evaluates caller input as
  code or interpolates it into a policy string.
- **No unsigned tag can publish.** CI runs `git verify-tag` against a pinned
  allowed-signers file before any publish job runs, and fails closed
  (`.github/workflows/release.yml:29-78`).
- **No `.pth` file in the tree.** CI fails if one appears
  (`.github/workflows/ci.yml:738-745`) — a Python import-time execution vector
  that can ride along in a model archive.
- **No unsigned artifact.** Binaries and the SBOM are signed with Sigstore
  Cosign, keyless via OIDC (`.github/workflows/release.yml:193,206,216`).

## Cryptography

- **TLS:** `rustls` 0.23 with the **ring** crypto provider — never
  `openssl`. (The `aws-lc-rs` crate is linked transitively because
  it's rustls's default feature, but Tracelane code paths use `ring`
  exclusively.)
- **Symmetric encryption (BYOK envelope):** AES-256-GCM via `ring`.
  Wire format prepends a version byte (`0x02` = v2) and binds the
  ciphertext to a caller-supplied AAD that includes the `tenant_id`
  and the asset kind (`provider-key:<tenant>:<provider>` or
  `audit-key:<tenant>`). Legacy v1 blobs (no version byte, empty AAD)
  are **rejected**, not decrypted — an empty AAD is what allowed the
  cross-tenant ciphertext swap this format exists to prevent
  (`crates/gateway/src/byok.rs:39`, `:171-182`).
- **Asymmetric (audit-ledger signing):** Ed25519 via `ring`.
  Per-tenant keypairs (Enterprise tier, gated by
  `entitlements::F_AUDIT_KEYPAIR`) generated and stored
  envelope-encrypted in `tenant_audit_keys` Postgres rows; lower
  tiers fall back to a process-global key from
  `TRACELANE_REKOR_SIGNING_KEY`. Private-key PKCS#8 bytes are
  wrapped in `secrecy::SecretBox` and zeroized on drop.
- **Hashing:** SHA-256 (audit row hash, RFC 6962 Merkle tree,
  MCP tool-schema fingerprinting).
- **Key derivation:** HKDF-SHA256 where applicable.

## Known limitations

- Free-tier rate limits (60 RPM) reduce abuse surface but do not eliminate it
- SLM judge inference latency (<50ms p99) means there is a brief window between
  request arrival and predictive decision — this is inherent to inline ML
- The ML tier is **not running**. `predictive/trajectory_guard.rs` and
  `predictive/slm_judge.rs` are registered but return a constant score with the
  `ort` inference call commented out, so they cannot currently produce a verdict.
  The rule-based detectors in `crates/gateway/src/predictive/` are registered, but
  most gate on payload fields (`mcp_server_name`, `tool_name`, `a2a_handoff`,
  `protocol`) that a `/v1/chat/completions` request does not carry, so **they do not
  fire on LLM traffic today** — the same disclosure as `README.md`. What does run
  inline on chat traffic is the guardrail rail set (`guardrail/rails/`: cost,
  secrets/PII, tool safety, lethal-trifecta, format, system-prompt leak, topic,
  injection). No F1 or detection-rate figure is published for the ML tier because
  none has been measured on a shipped model.

## Acknowledgments

We credit the following researchers whose public work informs Tracelane's
security design:
- Invariant Labs (MCP rug-pull attack research)
- Pipelock/Straiker (behavioral fingerprinting)
- CyberArk (Poison Everywhere injection surface)
- Microsoft AgentRx and Agent Governance Toolkit
- OWASP Agentic Top-10 working group

## Verifying release artifacts

All Tracelane release binaries are signed with [Sigstore Cosign](https://sigstore.dev)
keyless OIDC. Verify a downloaded binary:

```bash
cosign verify-blob \
  --bundle <binary>.cosign.bundle \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  <binary>
```

The Docker image is also signed. Verify:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/tracelane/gateway:latest
```

SBOM (CycloneDX JSON) is attached to every GitHub release as `sbom.cyclonedx.json`.
Build provenance is attached via GitHub `attest-build-provenance`. A verified
SLSA Level 3 attestation is **not** claimed — see the note above.

### How our scanners and CI actions are pinned

Our vulnerability scanner is not installed from a GitHub Action or a piped
installer script. CI downloads a **version-pinned Grype (Anchore) release
tarball, verifies its SHA-256 against a digest pinned in the workflow, and only
then extracts it** (`.github/workflows/security-scan.yml:84-113`) — a moved
release asset fails the checksum instead of executing. Every `uses:` in
`.github/workflows/` is **SHA-pinned to a specific commit** rather than a
floating tag, so a retargeted tag cannot change what runs — verifiable with
`grep -rhoE 'uses: [^ ]+' .github/workflows/ | grep -v '@[0-9a-f]\{40\}'`,
which returns nothing.
