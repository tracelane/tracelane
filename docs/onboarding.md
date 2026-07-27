# Onboarding — first tenant + first API key

This is the operator + customer flow for getting from "I'm signing up"
to "I have a live API key and my first request is in the dashboard."

---

## For the customer (browser-driven flow)

### 1. Sign up

Navigate to [`https://app.tracelane.dev/signup`](https://app.tracelane.dev/signup).
Authenticate via WorkOS Connect (Google / Microsoft / GitHub / SAML
for enterprises). On success, WorkOS posts `organization.created` and
`user.created` events to our webhook, which:

- Provisions a Tracelane `tenant` (free tier) — `tenant_id` derived
  deterministically from `SHA256("workos_org:" || workos_org_id)[..16]`
- Inserts a `users` row tied to that `tenant_id`

You're now logged in.

### 2. Issue your first API key

In the dashboard: **Settings → API Keys → Create**. We display the
raw key (`tlane_<base62>`) **once** — copy it now; we never store it
in plaintext (only a SHA-256 hash). Lost keys must be revoked +
re-issued.

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
changes apply within seconds via Polar webhook → Postgres
`tenants.set_plan_tier`.

---

## For the operator (self-host setup)

### Prerequisites

- Rust 1.87+, Node 20+, pnpm 11+
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
| `OTEL_EXPORTER_OTLP_ENDPOINT` | optional | `http://localhost:4317` for span emit |

Routes mount conditionally:

- `/v1/audit/export` — only with `CLICKHOUSE_URL`
- `/v1/billing/portal` — only with `POLAR_ACCESS_TOKEN`
- `/api/webhooks/polar` — only with `POLAR_WEBHOOK_SECRET`
- `/v1/webhooks/workos` — only with `WORKOS_WEBHOOK_SECRET`
- B1 prompt-promotion routes — only when built with feature
  `prompt-promotion-preview`

### 4. Start the services

```bash
cargo run -p gateway --release --features prompt-promotion-preview &
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
   `lookup_key`, so you can rename products without a redeploy:
   - `builder_v1` ($59)
   - `team_v1` ($249)
   - `business_v1` ($899)
   - `enterprise_v1` (from $2,999, custom)

   The `$0 OSS self-host` and `$0 hosted free` tiers have no Polar
   product — they're the default for unbilled tenants.
2. Create the metered add-on products with these `lookup_key`s:
   - `overage_v1` — trace overage meter ($1.20 per 10K)
   - `team_extra_seat_v1` / `business_extra_seat_v1` — seat overage ($19/seat/mo)
   - `audit_addon_v1` — $999/mo Audit SKU
   - `hipaa_gcp_addon_v1` — $2,000/mo Enterprise GCP/BAA opt-in

   (Five plans + four meters/add-ons = nine total Polar products.)
3. Create a **Webhook** (Standard Webhooks spec) at
   `$YOUR_GATEWAY/api/webhooks/polar` subscribed to the subscription
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

50 pain-point assertions + 8 fault-tolerance scenarios. CI fails on
any regression. Marketing claims on the public site auto-disable when
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
- [ ] R2 bucket + IAM configured for cold-tier Parquet
- [ ] OpenSSF Scorecard ≥ 9.0 on the public repo
- [ ] OSV-Scanner clean across Rust + TS + Python lockfiles
- [ ] All 50 pain-point evals green on the production gateway
- [ ] Dashboard `/trust` page reviewed by procurement / legal counsel
