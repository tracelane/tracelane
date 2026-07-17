# Migrating from LiteLLM to Tracelane

**Time to migrate:** <5 minutes  
**CVE context:** CVE-2026-33634 (CVSS 9.4, Mar 24, 2026) and CVE-2026-42208 (CVSS 9.3, Apr 24, 2026)

---

## Why migrate

Two critical vulnerabilities in 30 days made LiteLLM the most discussed migration
target in enterprise AI infrastructure in 2026:

- **CVE-2026-33634** (CVSS 9.4, Mar 24, 2026): Supply-chain compromise of
  LiteLLM v1.82.7/1.82.8 via a poisoned Trivy GitHub Action. Attackers injected
  malicious code into the release artifact.
- **CVE-2026-42208** (CVSS 9.3, Apr 24, 2026): Pre-auth SQL injection in
  LiteLLM ≤v1.83.6, exploited within 36 hours of public disclosure. Fixed in v1.83.7.

Tracelane provides everything LiteLLM does (BYOK proxy, 35+ providers, load balancing)
plus predictive guardrails, full-fidelity OTel traces, and a tamper-evident audit log.

---

## Step 1: Install the Tracelane CLI

```bash
npm install -g @tracelanedev/cli
```

Or run without installing:
```bash
npx @tracelanedev/cli import-litellm --config litellm_config.yaml
```

---

## Step 2: Generate a Tracelane gateway config

```bash
tlane import-litellm --config litellm_config.yaml --output tracelane.yaml
```

This reads your `litellm_config.yaml` and emits an equivalent Tracelane gateway
configuration. Supported translations:

| LiteLLM concept | Tracelane equivalent |
|---|---|
| `model_list` entries | `providers` array |
| `router_settings.routing_strategy` | `failover.strategy` |
| `router_settings.num_retries` | `failover.max_retries` |
| `general_settings.rate_limit_policy` | `rate_limit` |
| `litellm_settings.success_callback` | `telemetry.otlp_endpoint` |
| `environment_variables` | `.env` file (never in config) |

---

## Step 3: Set environment variables

```bash
export TRACELANE_API_KEY=<your-key>          # from tracelane.dev/dashboard
export TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev
# Or self-hosted:
# export TRACELANE_GATEWAY_URL=http://localhost:8080
```

---

## Step 4: Point your agents at Tracelane

Tracelane is OpenAI-API-compatible. Replace your LiteLLM proxy URL:

**Before:**
```python
client = openai.OpenAI(
    api_key="anything",
    base_url="http://localhost:4000"  # LiteLLM proxy
)
```

**After:**
```python
client = openai.OpenAI(
    api_key=os.environ["TRACELANE_API_KEY"],
    base_url=os.environ["TRACELANE_GATEWAY_URL"] + "/v1"
)
```

---

## What Tracelane would have caught about CVE-2026-42208

CVE-2026-42208 was a pre-auth SQL injection in LiteLLM's virtual key management
endpoint. Any request to `/key/generate` with a crafted payload could exfiltrate
the entire key database.

Tracelane's defense-in-depth would have mitigated this in three ways:

1. **No `/config/update` or admin endpoints** — Tracelane's gateway exposes no
   LiteLLM-style admin configuration endpoints. There is no equivalent surface.

2. **Cedar policy enforcement** — Tracelane uses Cedar (Apache 2.0) for all
   authorization decisions. No string-eval, no dynamic import of untrusted config.
   A SQL injection attack finds no parameterized query to inject into.

3. **Supply-chain hardening** — Tracelane's CI uses Grype (not Trivy) with a
   pinned release binary. All GitHub Actions are SHA-pinned. The LiteLLM CVE-2026-33634
   vector (poisoned Trivy action) doesn't exist in our pipeline.

---

## Verifying Tracelane releases

Unlike LiteLLM post-CVE, Tracelane's release artifacts are signed from day one:

```bash
# Verify a downloaded binary
cosign verify-blob \
  --bundle gateway-x86_64-unknown-linux-gnu.cosign.bundle \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  gateway-x86_64-unknown-linux-gnu

# Verify the Docker image
cosign verify \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/tracelane/gateway:latest
```

SLSA Build Level 3 provenance is attached to every release artifact.
CycloneDX SBOM is included.

---

## Feature comparison

| Feature | LiteLLM | Tracelane |
|---|---|---|
| BYOK proxy | ✅ | ✅ |
| Provider count | 100+ | 35 (V1), 100+ (V2) |
| Load balancing | ✅ | ✅ |
| OTel traces | Partial | ✅ Full `gen_ai.*` semconv |
| Predictive guardrails | ❌ | ✅ 10 inline, <30ms |
| Tamper-evident audit log | ❌ | ✅ Merkle chain + Rekor |
| EU AI Act Art. 12 export | ❌ | ✅ |
| License | MIT | Apache 2.0 |
| Signed releases | Post-CVE only | ✅ From day one |
| SLSA provenance | ❌ | ✅ Level 3 |

---

## Support

- Docs: https://tracelane.dev/docs
- GitHub: https://github.com/tracelane/tracelane
- Security issues: security@tracelane.dev (24-hour ack SLA)
