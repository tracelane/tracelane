<!-- tracelane:classification: PUBLIC -->
# Onboarding — first tenant + first API key

This is the operator + customer flow for getting from "I'm signing up"
to "I have a live API key and my first request is in the dashboard."

---

## For the customer (browser-driven flow)

### 1. Sign up

Navigate to [`https://app.tracelane.dev/sign-in`](https://app.tracelane.dev/sign-in)
(the same route handles first-time sign-up and returning sign-in).
Authenticate via WorkOS Connect (Google / Microsoft / GitHub / SAML
for enterprises). On success, WorkOS posts `organization.created` and
`user.created` events to our webhook, which:

- Provisions a Tracelane `tenant` (free tier) with a randomly generated
  `tenant_id` (UUID v4), stored against the WorkOS organization id under a
  unique index. The organization id is **not** the tenant id, and the tenant
  id is never derived from it — every resolution is a database lookup.
- Inserts a `users` row tied to that `tenant_id`

You're now logged in.

### 2. Issue your first API key

In the dashboard: **Settings → API Keys → Create**. We display the
raw key (`tlane_<base62>`) **once** — copy it now; we never store it
in plaintext (only a SHA-256 hash). Lost keys must be revoked + re-issued; revocation propagates within 60 seconds (an idle key may be accepted once more on its next use while the gateway re-checks it).

### 3. Configure your client

Two environment variables:

```bash
export TRACELANE_API_KEY="tlane_..."
export TRACELANE_GATEWAY_URL="https://gateway.tracelane.dev"
```

Then send your first request — see [Quickstart](quickstart.md).

### 4. (Optional) Upgrade to Pro / Enterprise

In the dashboard: **Settings → Billing → Manage**. We open a
Polar-hosted customer-portal session (`POST /v1/billing/portal`) where
you upgrade the plan, add payment method, and view invoices. Plan
changes are recorded within seconds via Polar webhook → Postgres
`tenants.set_plan_tier`, and the dashboard reflects them straight away.
**Your new limits apply to API traffic within 15 minutes** — the gateway
serves entitlements from a cache rather than reading the control plane on
every request, and that cache TTL is the bound.

---

## For the operator (self-host setup)

### Prerequisites

- Rust 1.95 (pinned by `rust-toolchain.toml`; the published-crate MSRV is 1.88), Node 22+, pnpm 9.15
- Postgres 17 (Neon-compatible)
- ClickHouse 24.12+
- NATS 2.10+ with JetStream
- Optional: Cloudflare R2 bucket + IAM, Sigstore Rekor URL override

### 1. Bring up the stack

```bash
git clone https://github.com/tracelane/tracelane.git
cd tracelane
docker compose -f infra/dev/docker-compose.yml up -d
```

This starts Postgres + ClickHouse + NATS + Grafana on local ports.

### 2. Apply migrations

```bash
./scripts/apply-migration-pg.sh   # tenants, api_keys, users, admin_audit
./scripts/apply-migration-03.sh   # B1 prompt-promotion schema in ClickHouse
```

The other ClickHouse migrations (audit_log, traces, spans) auto-apply
from `infra/dev/clickhouse/schema.sql` at container init.

### 3. Configure secrets

The gateway is configured exclusively via environment variables (no
config file by design — secrets live in your secrets store).

| Variable | Required | Purpose |
|---|---|---|
| `TRACELANE_PORT` | no (default 8080) | Listen port |
| `POSTGRES_URL` | for production | `postgres://user:pass@host:5432/tracelane` |
| `CLICKHOUSE_URL` | for production | `http://host:8123` |
| `WORKOS_CLIENT_ID` | for production | WorkOS Connect client id |
| `WORKOS_JWKS_URL` | optional override | default `https://api.workos.com/sso/jwks/{client_id}` |
| `WORKOS_ISSUER` | recommended | JWT issuer to validate |
| `WORKOS_AUDIENCE` | recommended | JWT audience to validate |
| `WORKOS_WEBHOOK_SECRET` | for SSO webhook | provisions tenants/users |
| `POLAR_ACCESS_TOKEN` | for billing | Polar organization access token (`secrecy::SecretString` wrapped) |
| `POLAR_WEBHOOK_SECRET` | for billing webhook | Polar dashboard → Webhooks (`polar_whs_…`) |
| `POLAR_EXPECTED_ORGANIZATION_ID` | for billing webhook | pins the Polar org the webhook secret was issued for |
| `TRACELANE_BILLING_RETURN_URL` | optional | default `https://app.tracelane.dev/billing` |
| `TRACELANE_REKOR_SIGNING_KEY` | for audit anchoring | PKCS#8 DER base64 Ed25519 key |
| `TRACELANE_REKOR_ANCHOR_EVERY` | optional | default 100 events per anchor batch |
| `TRACELANE_DEV_AUTH` | optional | set to `0` to disable dev auth fallback in debug builds |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | optional | `http://localhost:4318` for span emit — OTLP **HTTP**. `:4317` is the gRPC port and Tracelane does not serve it |

Routes mount conditionally:

- `/v1/audit/export` — only with `CLICKHOUSE_URL`
- `/v1/billing/portal` — only with `POLAR_ACCESS_TOKEN`
- `/api/webhooks/polar` — served by the DASHBOARD app (`apps/web`), not the gateway; only with `POLAR_WEBHOOK_SECRET`
- `/v1/webhooks/workos` — only with `WORKOS_WEBHOOK_SECRET`

### 4. Start the services

```bash
cargo run -p gateway --release &
cargo run -p ingest --release &
pnpm --filter @tracelanedev/web build && pnpm --filter @tracelanedev/web start &
```

### 5. Configure WorkOS

In the WorkOS dashboard:

1. Create an **Organization** for each customer tenant (or enable
   self-serve org creation if you want customers to manage their own)
2. Configure **Connections** for the SSO providers you want to support
   (Google, Microsoft, SAML, OIDC)
3. Configure a **Webhook** at `$YOUR_GATEWAY/v1/webhooks/workos`
   subscribed to: `organization.created`, `user.created`,
   `dsync.user.created` — copy the secret to `WORKOS_WEBHOOK_SECRET`
4. Configure the JWT **Issuer** and **Audience** values; set on the
   gateway via env

### 6. Configure Polar

Tracelane bills through **Polar.sh** (Polar handles Stripe under the
hood; we never call the Stripe API directly). In the Polar dashboard:

1. Create the base-plan **Products** and set each product's
   `metadata.lookup_key` (unprefixed) — the gateway maps plans by
   `lookup_key`, so you can rename products without a redeploy. Monthly and
   annual are separate Polar products:
   - `builder_v1` ($29) / `builder_v1_year` ($24/mo billed annually)
   - `team_v1` ($229) / `team_v1_year` ($190/mo billed annually)
   - `business_v1` ($799) / `business_v1_year` ($665/mo billed annually)
   - `enterprise_v1` (from $2,499, custom)

   The `$0 OSS self-host` and `$0 hosted free` tiers have no Polar
   product — they're the default for unbilled tenants. Seats are unlimited
   on every paid tier (Free stays capped at one) — there is no per-seat
   product to create.
2. Create the six usage meters with these `lookup_key`s / event names:
   - `ingest_gb` — $0.20/GB
   - `hot_gb_month` — laddered $16.00 / $8.00 / $4.50 / $3.00 per resident GB-month
   - `series` — $0.008/series-month
   - `scan_units` — $0.15/scan-unit
   - `cold_gb_month` — $0.08/GB-month
   - `eval_runs` — $0.005/judge run

   (Five plans × monthly+annual = ten base products, plus six meters. There
   is no paid audit product — `/v1/audit/export` does not yet meet the founder
   ruling's evidence-pack bar (spec `BILL-01` §10.4), so 7-year ledger
   retention folds into Enterprise instead of shipping as a paid SKU.)
3. Create a **Webhook** (Standard Webhooks spec) at
   `$YOUR_DASHBOARD/api/webhooks/polar` — the dashboard origin, NOT the gateway; the
   gateway has no Polar receiver and a webhook pointed there 404s, so no plan ever
   flips — subscribed to the subscription
   and order events (`subscription.created`, `subscription.updated`,
   `subscription.canceled`, `order.created`) — copy the signing secret
   (`polar_whs_…`) to `POLAR_WEBHOOK_SECRET`, and set
   `POLAR_EXPECTED_ORGANIZATION_ID` to your Polar organization id.
4. Issue an **Organization Access Token** and set it as
   `POLAR_ACCESS_TOKEN` — the gateway authenticates to the Polar API
   with `Authorization: Bearer $POLAR_ACCESS_TOKEN`.

### 7. Verify the stack

```bash
curl $TRACELANE_GATEWAY_URL/health
# {"status":"ok","service":"tracelane-gateway"}
```

```bash
curl -H "authorization: Bearer $TRACELANE_API_KEY" \
  $TRACELANE_GATEWAY_URL/v1/audit/export?since=2026-01-01 | head -3
```

You should see NDJSON audit rows. If the time range is empty, hit
`/v1/chat/completions` first to generate one.

### 8. Wire your evals

Run the V1 eval suite locally:

```bash
pnpm eval:run --suite=all
```

20 conformance evals — 10 fault-tolerance chaos scenarios, 7 gateway-correctness,
and one each for ingest-schema, PII-redaction and prompt-injection. CI fails on any regression. Marketing claims on the public site auto-disable when
the corresponding eval flips red on `main`.

---

## Production checklist

Before flipping a tenant to a paid plan:

- [ ] WorkOS Connect configured + tested (sign-up → tenant + user rows)
- [ ] Polar Products + Meters + Webhook configured
- [ ] `POLAR_WEBHOOK_SECRET` rotated + `POLAR_ACCESS_TOKEN` issued (org access token, least privilege)
- [ ] Audit anchoring keypair generated + `TRACELANE_REKOR_SIGNING_KEY` set
- [ ] `CLICKHOUSE_URL` pointing at production cluster (not dev compose)
- [ ] `POSTGRES_URL` pointing at Neon production branch
- [ ] OpenSSF Scorecard ≥ 9.0 on the public repo
- [ ] OSV-Scanner clean across Rust + TS + Python lockfiles
- [ ] All 20 conformance evals green on the production gateway
- [ ] Dashboard `/trust` page reviewed by procurement / legal counsel
