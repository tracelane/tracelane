CREATE TYPE "public"."cmk_algorithm" AS ENUM('ed25519', 'rsa-4096');--> statement-breakpoint
CREATE TYPE "public"."cmk_purpose" AS ENUM('provider-keys', 'trace-payload', 'all');--> statement-breakpoint
CREATE TYPE "public"."cmk_status" AS ENUM('active', 'rotating', 'revoked');--> statement-breakpoint
CREATE TYPE "public"."plan" AS ENUM('free', 'builder', 'team', 'business', 'enterprise');--> statement-breakpoint
CREATE TABLE "admin_audit_log" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_user_id" text NOT NULL,
	"actor_workspace_id" uuid,
	"action" text NOT NULL,
	"target_type" text NOT NULL,
	"target_id" text NOT NULL,
	"before_json" jsonb,
	"after_json" jsonb,
	"ip_addr" "inet",
	"user_agent" text
);
--> statement-breakpoint
CREATE TABLE "api_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"name" text NOT NULL,
	"key_hash" text NOT NULL,
	"key_prefix" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "cmk_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alias" text NOT NULL,
	"fingerprint" text NOT NULL,
	"algorithm" "cmk_algorithm" NOT NULL,
	"status" "cmk_status" DEFAULT 'active' NOT NULL,
	"purpose" "cmk_purpose" DEFAULT 'all' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"rotated_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "plan_entitlements" (
	"plan_lookup_key" text PRIMARY KEY NOT NULL,
	"seat_cap_included" integer DEFAULT 1 NOT NULL,
	"seat_cap_max" integer DEFAULT 1 NOT NULL,
	"retention_days" integer DEFAULT 7 NOT NULL,
	"trace_quota_monthly" bigint DEFAULT 10000 NOT NULL,
	"gateway_quota_monthly" bigint DEFAULT 10000 NOT NULL,
	"overage_hard_cap_multiplier" numeric(4, 1) DEFAULT '1.0' NOT NULL,
	"overage_price_per_10k_usd" numeric(6, 2) DEFAULT '0.00' NOT NULL,
	"f_pr7_trajectory" boolean DEFAULT false NOT NULL,
	"f_pr8_argdrift" boolean DEFAULT false NOT NULL,
	"f_pr9_a2a_handoff" boolean DEFAULT false NOT NULL,
	"f_pr10_inline_slm_judge" boolean DEFAULT false NOT NULL,
	"f_pr11_slo_drift" boolean DEFAULT false NOT NULL,
	"f_pr12_langgraph_branch" boolean DEFAULT false NOT NULL,
	"f_cohort_baselines" boolean DEFAULT false NOT NULL,
	"f_hipaa_gcp_addon" boolean DEFAULT false NOT NULL,
	"f_audit_addon" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tenants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workos_org_id" text NOT NULL,
	"stripe_customer_id" text,
	"polar_customer_id" text,
	"polar_subscription_id" text,
	"plan" "plan" DEFAULT 'builder' NOT NULL,
	"audit_enabled" boolean DEFAULT false NOT NULL,
	"slack_webhook_url" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "webhook_events" (
	"source" text NOT NULL,
	"event_id" text NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "webhook_events_source_event_id_pk" PRIMARY KEY("source","event_id")
);
--> statement-breakpoint
CREATE TABLE "workspace_entitlements" (
	"tenant_id" uuid PRIMARY KEY NOT NULL,
	"plan_lookup_key" text NOT NULL,
	"seat_cap_included" integer,
	"seat_cap_max" integer,
	"retention_days" integer,
	"trace_quota_monthly" bigint,
	"gateway_quota_monthly" bigint,
	"overage_hard_cap_multiplier" numeric(4, 1),
	"overage_price_per_10k_usd" numeric(6, 2),
	"f_pr7_trajectory" boolean,
	"f_pr8_argdrift" boolean,
	"f_pr9_a2a_handoff" boolean,
	"f_pr10_inline_slm_judge" boolean,
	"f_pr11_slo_drift" boolean,
	"f_pr12_langgraph_branch" boolean,
	"f_cohort_baselines" boolean,
	"f_hipaa_gcp_addon" boolean,
	"f_audit_addon" boolean,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cmk_keys" ADD CONSTRAINT "cmk_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD CONSTRAINT "workspace_entitlements_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD CONSTRAINT "workspace_entitlements_plan_lookup_key_plan_entitlements_plan_lookup_key_fk" FOREIGN KEY ("plan_lookup_key") REFERENCES "public"."plan_entitlements"("plan_lookup_key") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_admin_audit_workspace" ON "admin_audit_log" USING btree ("actor_workspace_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "idx_admin_audit_target" ON "admin_audit_log" USING btree ("target_type","target_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "api_keys_tenant_id_idx" ON "api_keys" USING btree ("tenant_id");--> statement-breakpoint
CREATE UNIQUE INDEX "api_keys_key_hash_idx" ON "api_keys" USING btree ("key_hash");--> statement-breakpoint
CREATE INDEX "cmk_keys_tenant_id_idx" ON "cmk_keys" USING btree ("tenant_id");--> statement-breakpoint
CREATE UNIQUE INDEX "cmk_keys_tenant_fingerprint_idx" ON "cmk_keys" USING btree ("tenant_id","fingerprint");--> statement-breakpoint
CREATE UNIQUE INDEX "tenants_workos_org_id_idx" ON "tenants" USING btree ("workos_org_id");--> statement-breakpoint
CREATE INDEX "webhook_events_received_at_idx" ON "webhook_events" USING btree ("received_at");--> statement-breakpoint
CREATE INDEX "workspace_entitlements_plan_idx" ON "workspace_entitlements" USING btree ("plan_lookup_key");