-- Migration 0001 — reconcile gateway<->prod control-plane schema (ADR-042).
--
-- Adds the 4 Postgres tables the gateway reads/writes that were never in the
-- peppered-HMAC columns on api_keys. **Idempotent** (IF NOT EXISTS / DROP NOT
-- NULL) because prod was push-provisioned — there is no `drizzle` migrate
-- tracking table, so this is applied directly via psql, not `drizzle-kit
-- migrate`. Deliberately does NOT touch `tenants`: `archived_at` and the `plan`
-- DEFAULT 'free' are already live in prod (ADR-040 push); drizzle-kit only
-- emitted them because the 0000 baseline snapshot predates those pushes.

-- ── BYOK provider keys ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS "provider_keys" (
	"tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
	"provider_id" text NOT NULL,
	"ciphertext_b64" text NOT NULL,
	"last4" text NOT NULL,
	"created_at" timestamptz NOT NULL DEFAULT now(),
	"updated_at" timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT "provider_keys_tenant_id_provider_id_pk" PRIMARY KEY ("tenant_id","provider_id")
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "provider_keys_tenant_idx" ON "provider_keys" ("tenant_id");
--> statement-breakpoint

-- ── Tamper-evident audit ledger ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS "audit_chain_state" (
	"tenant_id" uuid PRIMARY KEY REFERENCES "tenants"("id") ON DELETE CASCADE,
	"last_seq" bigint NOT NULL,
	"last_row_hash" bytea NOT NULL,
	"updated_at" timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "tenant_audit_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
	"encrypted_private_key" text NOT NULL,
	"public_key_b64" text NOT NULL DEFAULT '',
	"rotated_from" uuid,
	"created_at" timestamptz NOT NULL DEFAULT now(),
	"revoked_at" timestamptz
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "tenant_audit_keys_one_per_tenant" ON "tenant_audit_keys" ("tenant_id");
--> statement-breakpoint

-- ── Payment events (x402 / AP2 / ACP) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS "payment_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
	"agent_id" text,
	"trace_id" uuid,
	"span_id" uuid,
	"event_type" text NOT NULL,
	"amount_usd" numeric(20, 8),
	"recipient" text,
	"mandate_id" text,
	"payload" jsonb,
	"created_at" timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "payment_events_tenant_idx" ON "payment_events" ("tenant_id","created_at" DESC);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "payment_events_agent_idx" ON "payment_events" ("tenant_id","agent_id","created_at" DESC);
--> statement-breakpoint

ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "lookup_hash" bytea;
--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "argon2id_phc" text;
--> statement-breakpoint
ALTER TABLE "api_keys" ALTER COLUMN "key_hash" DROP NOT NULL;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "api_keys_lookup_hash_idx" ON "api_keys" ("lookup_hash");
