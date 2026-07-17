CREATE TABLE "users" (
	"user_id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"email" text NOT NULL,
	"workos_user_id" text,
	"name" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_login_at" timestamp with time zone,
	CONSTRAINT "users_email_unique" UNIQUE("email"),
	CONSTRAINT "users_workos_user_id_unique" UNIQUE("workos_user_id")
);
--> statement-breakpoint
ALTER TABLE "plan_entitlements" ADD COLUMN "f_guardrail_r2" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "plan_entitlements" ADD COLUMN "f_guardrail_r3_pinning" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "plan_entitlements" ADD COLUMN "f_guardrail_r4" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "plan_entitlements" ADD COLUMN "f_guardrail_r5" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "plan_entitlements" ADD COLUMN "f_guardrail_r6" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "plan_entitlements" ADD COLUMN "f_guardrail_r7" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "name" text;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN "f_guardrail_r2" boolean;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN "f_guardrail_r3_pinning" boolean;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN "f_guardrail_r4" boolean;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN "f_guardrail_r5" boolean;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN "f_guardrail_r6" boolean;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN "f_guardrail_r7" boolean;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "users_tenant_id_idx" ON "users" USING btree ("tenant_id");