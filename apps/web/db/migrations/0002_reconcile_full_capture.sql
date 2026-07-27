ALTER TABLE "plan_entitlements" ADD COLUMN "f_full_capture" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "sampling_policy" text DEFAULT 'tail' NOT NULL;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "force_tail" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "tenants" ADD COLUMN "billing_email" text;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN "f_full_capture" boolean;