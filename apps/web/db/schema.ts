/**
 * Drizzle ORM schema for Tracelane's Neon Postgres tenant database.
 *
 * Stores tenant metadata, BYOK CMK keys, API keys, and billing state.
 * ClickHouse holds the hot trace/span data; Postgres holds the cold
 * configuration and billing state.
 *
 * tenant_id = WorkOS organizationId — the primary tenant scoping key.
 * Every table has tenant_id as the first column and indexed.
 */

import { sql } from "drizzle-orm";
import {
	bigint,
	bigserial,
	boolean,
	check,
	customType,
	doublePrecision,
	index,
	inet,
	integer,
	jsonb,
	numeric,
	pgEnum,
	pgTable,
	primaryKey,
	text,
	timestamp,
	uniqueIndex,
	uuid,
} from "drizzle-orm/pg-core";

// Raw bytes column (Postgres `bytea`). Drizzle has no native bytea, so define it
// once here. Used for the peppered-HMAC api-key lookup (`api_keys.lookup_hash`)
// and the audit hash-chain head (`audit_chain_state.last_row_hash`) — both
// operate on bytes end-to-end; only the wire boundary hex/base64-encodes.
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
	dataType() {
		return "bytea";
	},
});

// ── Tenants ──────────────────────────────────────────────────────────────────

// `free` is the unbilled/canceled tier (free_v1). Listed first so a canceled
// subscription can set tenants.plan = 'free' (the Polar webhook). The column
// DEFAULT is 'free' in prod (verified 2026-06-08), so a fresh unbilled signup
// resolves to free-tier entitlements until a Polar event / manual grant elevates
// it — the safe default (no free Builder quota leak).
export const planEnum = pgEnum("plan", [
	"free",
	"builder",
	"team",
	"business",
	"enterprise",
]);

export const tenants = pgTable(
	"tenants",
	{
		id: uuid("id").defaultRandom().primaryKey(),
		workosOrgId: text("workos_org_id").notNull(),
		// Legacy Stripe column kept for back-compat during the Phase-2
		// migration; new code reads/writes polarCustomerId. Dropped in
		// a follow-up migration once telemetry confirms zero new writes.
		stripeCustomerId: text("stripe_customer_id"),
		polarCustomerId: text("polar_customer_id"),
		polarSubscriptionId: text("polar_subscription_id"),
		// Fresh/unbilled signups are 'free' until the Polar webhook (or a manual
		// grant) elevates them. Previously 'builder', which gave new signups
		// Builder entitlements (150K traces) for free.
		plan: planEnum("plan").default("free").notNull(),
		auditEnabled: boolean("audit_enabled").default(false).notNull(),
		// Per-tenant Slack webhook receiver for quota-exceeded 429 alerts
		// (migration 09_pricing_v2_entitlements). Nullable; nullable POST is
		// a no-op in the gateway.
		slackWebhookUrl: text("slack_webhook_url"),
		// ADR-048 D1: the tenant's capture preference WITHIN what f_full_capture
		// entitles. 'tail' (default) | 'full'. Only honoured when full capture
		// is granted; a non-entitled 'full' resolves to tail (fail-safe cheap).
		samplingPolicy: text("sampling_policy").default("tail").notNull(),
		// ADR-048 D4.4: operational force-tail kill-switch, independent of
		// entitlements. TRUE bounds a runaway tenant without a deploy; does not
		// override the Audit-SKU forced-full guarantee.
		forceTail: boolean("force_tail").default(false).notNull(),
		// ADR-048 D5: billing contact for the quota-breach notice (nullable).
		billingEmail: text("billing_email"),
		// GWY-43: workspace-wide monthly USD spend ceiling across ALL keys.
		// NULL = uncapped. Distinct from the plan's TRACE quota: this is a
		// customer-set DOLLAR limit, and it composes with the per-key budget —
		// a request must pass both. Applied by migration 0029 (un-journaled).
		//
		// "Per-team" in the Sprint-1 brief means this: there is no `teams` table
		// and never was — a team IS the workspace (WorkOS org → tenants row).
		budgetUsdMonthly: numeric("budget_usd_monthly", {
			precision: 12,
			scale: 4,
		}),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		updatedAt: timestamp("updated_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		// Tenant kill-switch / soft-delete (ADR-040 D2). Non-NULL = service cut,
		// data retained for audit retention. The gateway filters
		// `archived_at IS NULL` on every tenant read. Admin set/unset path: V1
		// manual SQL, UI later (see PROGRESS Eng-queue).
		archivedAt: timestamp("archived_at", { withTimezone: true }),
		// Org display name (nullable). Retained in prod from an earlier push;
		// re-added to schema.ts per so Drizzle matches reality. ADR-040
		// dropped it from the gateway (WorkOS owns org names — the gateway never
		// reads it), but `drizzle-kit push` never dropped the column, so it
		// persists. Keeping it here is the honest, non-destructive reconcile.
		name: text("name"),
	},
	(t) => [
		uniqueIndex("tenants_workos_org_id_idx").on(t.workosOrgId),
		//  LOW (defense in depth): the disposable E2E-bypass tenant id
		// (lib/e2e-auth.ts E2E_TEST_TENANT_ID) must NEVER be a real tenant row.
		// The app-layer mint already fails closed; this DB CHECK makes a real row
		// with that id physically impossible (e.g. a stray seed / manual insert).
		check(
			"tenants_id_not_e2e_disposable",
			sql`${t.id} <> '00000000-0000-4000-8000-0000e2e2e2e2'::uuid`,
		),
	],
);

export type Tenant = typeof tenants.$inferSelect;

// ── Pricing v2 entitlements (migration 09) ───────────────────────────────────
// `plan_entitlements`     — per-plan defaults (one row per plan lookup_key).
// `workspace_entitlements` — per-tenant overrides; NULL means inherit.
// Deny-overrides-grant per ADR-009 §7.4.9 — a FALSE here overrides a TRUE
// in plan_entitlements.

export const planEntitlements = pgTable("plan_entitlements", {
	planLookupKey: text("plan_lookup_key").primaryKey(),
	seatCapIncluded: integer("seat_cap_included").notNull().default(1),
	seatCapMax: integer("seat_cap_max").notNull().default(1),
	retentionDays: integer("retention_days").notNull().default(7),
	traceQuotaMonthly: bigint("trace_quota_monthly", { mode: "number" })
		.notNull()
		.default(10000),
	gatewayQuotaMonthly: bigint("gateway_quota_monthly", { mode: "number" })
		.notNull()
		.default(10000),
	overageHardCapMultiplier: numeric("overage_hard_cap_multiplier", {
		precision: 4,
		scale: 1,
	})
		.notNull()
		.default("1.0"),
	overagePricePer10kUsd: numeric("overage_price_per_10k_usd", {
		precision: 6,
		scale: 2,
	})
		.notNull()
		.default("0.00"),
	fPr7Trajectory: boolean("f_pr7_trajectory").notNull().default(false),
	fPr8Argdrift: boolean("f_pr8_argdrift").notNull().default(false),
	fPr9A2aHandoff: boolean("f_pr9_a2a_handoff").notNull().default(false),
	fPr10InlineSlmJudge: boolean("f_pr10_inline_slm_judge")
		.notNull()
		.default(false),
	fPr11SloDrift: boolean("f_pr11_slo_drift").notNull().default(false),
	fPr12LanggraphBranch: boolean("f_pr12_langgraph_branch")
		.notNull()
		.default(false),
	fCohortBaselines: boolean("f_cohort_baselines").notNull().default(false),
	// NOT A SHIPPED ENTITLEMENT. There is no HIPAA BAA and no GCP deployment —
	// nothing in this repo ever sets this flag TRUE: `seed.mjs` does not seed
	// `hipaa_gcp_addon_v1`, and the Polar webhook explicitly refuses to auto-wire
	// the grant (`app/api/webhooks/polar/route.ts` handleAddOnChange). The column
	// exists in Neon, so it stays here for Drizzle parity; removing it is a
	// hand-written migration, not an edit to this file.
	fHipaaGcpAddon: boolean("f_hipaa_gcp_addon").notNull().default(false),
	fAuditAddon: boolean("f_audit_addon").notNull().default(false),
	// ADR-048 D2: full-capture gate. Business + Enterprise base = TRUE; others
	// FALSE. Audit-SKU-active forces full regardless (resolved in entitlements).
	fFullCapture: boolean("f_full_capture").notNull().default(false),
	//  ADR-009: Prompt-Promotion WRITE workflow (promote/rollback
	// observe). Team+ = TRUE (seeded); Builder is read-only, Free none.
	fPromptPromotionWrite: boolean("f_prompt_promotion_write")
		.notNull()
		.default(false),
	// User-facing alerting (ADR-059; migration 0012). DARK on every plan until the
	// founder flips it at DoD close; a per-tenant workspace override grants early.
	fAlerts: boolean("f_alerts").notNull().default(false),
	// ── Sprint 3, the eval loop (migration 0030) ───────────────────────────────
	// Four flags, one migration, and the ORDER is the point: each column lands in
	// Neon BEFORE the gateway that reads it deploys (CLAUDE.md §4.0). Get it
	// backwards and nothing 500s — which is precisely the danger. The gateway
	// resolves EVERY flag in ONE SELECT naming each column by name
	// (`crates/gateway/src/entitlement_cache.rs:540-570`), so one absent column
	// fails that whole statement for every tenant; the miss path then serves
	// `deny_all()` because a freshly deployed process has no last-known grant
	// (`entitlement_cache.rs:459-491`). Every gated feature — guardrail rails,
	// prompt promotion, alerts, audit self-verify — goes OFF for every tenant,
	// reported as a `warn!` and a counter, never as an error a caller can see.
	// Plan default is FALSE for the same reason every other flag's is: an absent
	// or unseeded control plane must resolve to the UNPRIVILEGED state
	// (`.claude/rules/tenancy.md`). The tier split below is seeded, not defaulted.
	//
	// EVL-04 datasets + the golden schema. BUILDER+ = TRUE (spec §9 Q2) — the one
	// flag of the four that is not Team+: datasets are table-stakes parity
	// against LiteLLM/Langfuse/Braintrust, and gating them at Team loses the
	// comparison before it starts.
	fDatasets: boolean("f_datasets").notNull().default(false),
	// EVL-02 experiments — a dataset × a prompt version, run and diffed
	// side-by-side. Team+ = TRUE (seeded), alongside f_prompt_promotion_write,
	// which the promote step at the end of an experiment already requires; a
	// tenant able to run one but never act on it is the dormant shape.
	fExperiments: boolean("f_experiments").notNull().default(false),
	// EVL-28 online evals — sampled scoring of live production traffic. Team+ =
	// TRUE (seeded). Spends the tenant's provider money per sampled request, so
	// it is deliberately not a Builder default.
	fOnlineEvals: boolean("f_online_evals").notNull().default(false),
	// EVL-29 annotation / review queues over the OBS-18 trace_annotations store.
	// Team+ = TRUE (seeded) — a review queue is a multi-seat workflow, and
	// Builder is a one-seat plan (seat_cap_max = 1).
	fAnnotationQueues: boolean("f_annotation_queues").notNull().default(false),
	// Inline guardrail V1 rails (infra migration 12 → reconciled into Drizzle in
	// they were prod-only, hand-applied). Gated rails default OFF for
	// every plan (guardrail spec §2.7); R1/R3-schema/R8 are always-on and carry
	// no flag. A workspace override or a future pricing-ADR seed flips one on.
	fGuardrailR2: boolean("f_guardrail_r2").notNull().default(false),
	fGuardrailR3Pinning: boolean("f_guardrail_r3_pinning")
		.notNull()
		.default(false),
	fGuardrailR4: boolean("f_guardrail_r4").notNull().default(false),
	fGuardrailR5: boolean("f_guardrail_r5").notNull().default(false),
	fGuardrailR6: boolean("f_guardrail_r6").notNull().default(false),
	fGuardrailR7: boolean("f_guardrail_r7").notNull().default(false),
	// ADR-066: free-tier audit self-verify. Default TRUE on every plan — a
	// tenant SEEs + verifies their OWN recent chain in-app. Distinct from the
	// paid fAuditAddon (Article-12 evidence-pack export).
	fAuditSelfverify: boolean("f_audit_selfverify").notNull().default(true),
	createdAt: timestamp("created_at", { withTimezone: true })
		.defaultNow()
		.notNull(),
	updatedAt: timestamp("updated_at", { withTimezone: true })
		.defaultNow()
		.notNull(),
});

export type PlanEntitlement = typeof planEntitlements.$inferSelect;

export const workspaceEntitlements = pgTable(
	"workspace_entitlements",
	{
		tenantId: uuid("tenant_id")
			.primaryKey()
			.references(() => tenants.id, { onDelete: "cascade" }),
		planLookupKey: text("plan_lookup_key")
			.notNull()
			.references(() => planEntitlements.planLookupKey),
		// All nullable: NULL == inherit from plan_entitlements.
		seatCapIncluded: integer("seat_cap_included"),
		seatCapMax: integer("seat_cap_max"),
		retentionDays: integer("retention_days"),
		traceQuotaMonthly: bigint("trace_quota_monthly", { mode: "number" }),
		gatewayQuotaMonthly: bigint("gateway_quota_monthly", { mode: "number" }),
		overageHardCapMultiplier: numeric("overage_hard_cap_multiplier", {
			precision: 4,
			scale: 1,
		}),
		overagePricePer10kUsd: numeric("overage_price_per_10k_usd", {
			precision: 6,
			scale: 2,
		}),
		fPr7Trajectory: boolean("f_pr7_trajectory"),
		fPr8Argdrift: boolean("f_pr8_argdrift"),
		fPr9A2aHandoff: boolean("f_pr9_a2a_handoff"),
		fPr10InlineSlmJudge: boolean("f_pr10_inline_slm_judge"),
		fPr11SloDrift: boolean("f_pr11_slo_drift"),
		fPr12LanggraphBranch: boolean("f_pr12_langgraph_branch"),
		fCohortBaselines: boolean("f_cohort_baselines"),
		fHipaaGcpAddon: boolean("f_hipaa_gcp_addon"),
		fAuditAddon: boolean("f_audit_addon"),
		// ADR-048 D2: per-tenant full-capture override (NULL = inherit plan).
		fFullCapture: boolean("f_full_capture"),
		//  ADR-009: per-tenant prompt-promotion-write override.
		fPromptPromotionWrite: boolean("f_prompt_promotion_write"),
		// ADR-059 alerting override (NULL = inherit plan).
		fAlerts: boolean("f_alerts"),
		// Sprint 3 eval-loop per-tenant overrides (migration 0030). NULLABLE and
		// WITHOUT a default, deliberately and identically to every flag above:
		// NULL = inherit the plan, and a FALSE here beats a plan-level TRUE
		// (deny-overrides-grant, ADR-009 §7.4.9 — the gateway resolves
		// `COALESCE(we.f_x, pe.f_x)`). Give one of these a NOT NULL DEFAULT and
		// the override table stops meaning "inherit", silently: every tenant row
		// would read FALSE and no plan grant would ever reach them.
		fDatasets: boolean("f_datasets"),
		fExperiments: boolean("f_experiments"),
		fOnlineEvals: boolean("f_online_evals"),
		fAnnotationQueues: boolean("f_annotation_queues"),
		// Per-tenant guardrail-rail overrides (NULL = inherit plan). infra
		// migration 12 → reconciled into Drizzle in (were prod-only).
		fGuardrailR2: boolean("f_guardrail_r2"),
		fGuardrailR3Pinning: boolean("f_guardrail_r3_pinning"),
		fGuardrailR4: boolean("f_guardrail_r4"),
		fGuardrailR5: boolean("f_guardrail_r5"),
		fGuardrailR6: boolean("f_guardrail_r6"),
		fGuardrailR7: boolean("f_guardrail_r7"),
		// ADR-066: per-tenant audit self-verify override (NULL = inherit plan;
		// FALSE switches off the default-TRUE free grant, deny-overrides-grant).
		fAuditSelfverify: boolean("f_audit_selfverify"),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		updatedAt: timestamp("updated_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [index("workspace_entitlements_plan_idx").on(t.planLookupKey)],
);

export type WorkspaceEntitlement = typeof workspaceEntitlements.$inferSelect;

// ── Alerting (ADR-059 — customer-facing) ─────────────────────────────────────

// A Slack-compatible webhook destination. All kinds POST the same Slack
// `{"text":…}` payload; Discord accepts it at `<webhook>/slack`, so `kind` is a
// UI hint only, not a code branch.
export const alertDestinations = pgTable(
	"alert_destinations",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		name: text("name").notNull(),
		kind: text("kind").notNull().default("slack"),
		url: text("url").notNull(),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [index("alert_destinations_tenant_idx").on(t.tenantId)],
);
export type AlertDestination = typeof alertDestinations.$inferSelect;

// One alert rule: (metric, comparator, threshold, window) → destination.
// `metric` ∈ {error_rate, burn_rate, latency_p95, cost_usd, quota_pct}.
// last_state/last_fired_at drive edge-triggered firing + a re-fire cooldown.
export const alertRules = pgTable(
	"alert_rules",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		metric: text("metric").notNull(),
		comparator: text("comparator").notNull().default("gt"),
		threshold: doublePrecision("threshold").notNull(),
		windowMinutes: integer("window_minutes").notNull().default(60),
		destinationId: uuid("destination_id")
			.notNull()
			.references(() => alertDestinations.id, { onDelete: "cascade" }),
		enabled: boolean("enabled").notNull().default(true),
		lastState: text("last_state").notNull().default("ok"),
		lastFiredAt: timestamp("last_fired_at", { withTimezone: true }),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		updatedAt: timestamp("updated_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [index("alert_rules_tenant_enabled_idx").on(t.tenantId, t.enabled)],
);
export type AlertRule = typeof alertRules.$inferSelect;

// ── CMK / BYOK keys ──────────────────────────────────────────────────────────

export const cmkAlgorithmEnum = pgEnum("cmk_algorithm", [
	"ed25519",
	"rsa-4096",
]);
export const cmkStatusEnum = pgEnum("cmk_status", [
	"active",
	"rotating",
	"revoked",
]);
export const cmkPurposeEnum = pgEnum("cmk_purpose", [
	"provider-keys",
	"trace-payload",
	"all",
]);

export const cmkKeys = pgTable(
	"cmk_keys",
	{
		id: uuid("id").defaultRandom().primaryKey(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		alias: text("alias").notNull(),
		fingerprint: text("fingerprint").notNull(),
		algorithm: cmkAlgorithmEnum("algorithm").notNull(),
		status: cmkStatusEnum("status").default("active").notNull(),
		purpose: cmkPurposeEnum("purpose").default("all").notNull(),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		rotatedAt: timestamp("rotated_at", { withTimezone: true }),
	},
	(t) => [
		index("cmk_keys_tenant_id_idx").on(t.tenantId),
		uniqueIndex("cmk_keys_tenant_fingerprint_idx").on(
			t.tenantId,
			t.fingerprint,
		),
	],
);

export type CmkKey = typeof cmkKeys.$inferSelect;

// ── API keys ─────────────────────────────────────────────────────────────────
// Gateway keys for authenticating agent traffic. Auth is the peppered-HMAC
// + Argon2id scheme (ADR-042), matching crates/gateway/src/db/api_keys.rs:
//   • lookup_hash  = HMAC-SHA256(TRACELANE_APIKEY_PEPPER, key_body) — indexed lookup
//   • argon2id_phc = Argon2id(key_body) PHC string                  — KDF verify
// The web minter and the gateway MUST HMAC with the SAME pepper. key_hash (legacy
// bare SHA-256) is nullable + deprecated — dropped in a follow-up once no rows
// rely on it. Raw key shown once at creation; key material never stored.

export const apiKeys = pgTable(
	"api_keys",
	{
		id: uuid("id").defaultRandom().primaryKey(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		name: text("name").notNull(),
		// Peppered HMAC-SHA256(key_body): deterministic, indexed, DB-dump-resistant.
		// The gateway hot-path lookup column (WHERE lookup_hash = $1).
		lookupHash: bytea("lookup_hash"),
		// Argon2id PHC string of key_body — verified after a lookup_hash hit.
		argon2idPhc: text("argon2id_phc"),
		// Legacy bare SHA-256(full key) hex — nullable + deprecated (rows).
		keyHash: text("key_hash"),
		keyPrefix: text("key_prefix").notNull(),
		// WorkOS user id (`Claims.sub`) of the minting user, recorded by the
		// gateway mint path. Nullable: pre-0011 keys have no recorded minter and
		// are not revoked on member removal (unattributable). IDENTITY_TEAM_SPEC §3.
		mintedBy: text("minted_by"),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
		revokedAt: timestamp("revoked_at", { withTimezone: true }),
		// ── A13 / SET-20: scoped, time-bounded, budget-capped keys ──────────
		// Applied to Neon by migration 0024 (un-journaled) BEFORE the gateway
		// that reads them deploys — the ordering rule in apps/web/CLAUDE.md.
		//
		// ALL THREE ARE NULLABLE, and NULL preserves today's behaviour, so the
		// existing keys keep working unchanged. That is a BACKWARDS-COMPATIBILITY
		// choice for existing rows, NOT a safe default for new ones: the mint
		// route requires an explicit scope. Do not read the column's permissive
		// NULL as the policy.
		//
		//   scope              NULL = full API surface (legacy) · never `{}`
		//   expiresAt          NULL = never expires (legacy)
		//   budgetUsdMonthly   NULL = uncapped
		//
		// `{}` is rejected at the DB by `api_keys_scope_not_empty_chk` (falsified
		// against prod 2026-08-12) because an empty array is ambiguous between
		// "no permissions" and "all permissions"; NULL is the one unscoped form.
		scope: text("scope").array(),
		expiresAt: timestamp("expires_at", { withTimezone: true }),
		budgetUsdMonthly: numeric("budget_usd_monthly", {
			precision: 12,
			scale: 4,
		}),
		// ── GWY-43: per-key rate limit ──────────────────────────────────────
		// Applied to Neon by migration 0029 (un-journaled) BEFORE the gateway
		// that reads it deploys — the gateway's hot-path auth SELECT reads this
		// column, so a gateway ahead of the migration 500s on every API-key
		// request rather than degrading.
		//
		//   rateLimitRpm  NULL = inherit the tenant's plan tier (pre-GWY-43)
		//
		// `api_keys_rate_limit_rpm_positive_chk` rejects 0: a key that can never
		// be used is a foot-gun, and `revokedAt` already switches a key off.
		rateLimitRpm: integer("rate_limit_rpm"),
	},
	(t) => [
		index("api_keys_tenant_id_idx").on(t.tenantId),
		// Only keys that actually expire are of interest to the expiry sweep.
		index("api_keys_expires_at_idx")
			.on(t.expiresAt)
			.where(sql`${t.expiresAt} IS NOT NULL AND ${t.revokedAt} IS NULL`),
		uniqueIndex("api_keys_lookup_hash_idx").on(t.lookupHash),
		// PARTIAL unique index: `key_hash` is the LEGACY column, always
		// NULL for keys minted by the current route. A plain unique index that
		// treats NULLs as not-distinct rejects the 2nd NULL row → the "can't add a
		// second key" 500. Excluding NULLs keeps uniqueness for legacy non-null
		// key_hash values while allowing any number of new (NULL) rows.
		uniqueIndex("api_keys_key_hash_idx")
			.on(t.keyHash)
			.where(sql`${t.keyHash} IS NOT NULL`),
	],
);

export type ApiKey = typeof apiKeys.$inferSelect;

// ── Webhook dedup ledger ──────────────────────────────────────────────────────
// Idempotency primitive for inbound webhooks (Polar). A row records that
// `(source, event_id)` was already processed; `try_record` inserts ON CONFLICT
// DO NOTHING after successful dispatch (record AFTER, not before). Mirrors
// infra/dev/postgres/migrations/04_webhook_events.sql.

export const webhookEvents = pgTable(
	"webhook_events",
	{
		source: text("source").notNull(),
		eventId: text("event_id").notNull(),
		receivedAt: timestamp("received_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [
		primaryKey({ columns: [t.source, t.eventId] }),
		index("webhook_events_received_at_idx").on(t.receivedAt),
	],
);

export type WebhookEvent = typeof webhookEvents.$inferSelect;

// ── Admin audit log ───────────────────────────────────────────────────────────
// Durable trail of mutating admin actions (ADR-031). Written via raw SQL in
// lib/admin-audit.ts (db.execute), so this Drizzle model exists so the table is
// provisioned by drizzle-kit push — it mirrors
// infra/dev/postgres/migrations/11_admin_audit_log.sql. Actor/target columns are
// denormalised so the row survives hard-deletes of the underlying entity.

export const adminAuditLog = pgTable(
	"admin_audit_log",
	{
		id: bigserial("id", { mode: "number" }).primaryKey(),
		occurredAt: timestamp("occurred_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		// WorkOS user id (opaque string) — TEXT, not a FK into `users`:
		// admin_audit_log DENORMALISES the actor id so the row survives a
		// hard-delete of the user/tenant it references (compliance trail). The
		// `users` table does exist (gateway-provisioned via the WorkOS webhook;
		// see `users` below, added in) — this column just doesn't point at it.
		actorUserId: text("actor_user_id").notNull(),
		// Internal tenant UUID; nullable for cross-workspace operator actions.
		actorWorkspaceId: uuid("actor_workspace_id"),
		action: text("action").notNull(),
		targetType: text("target_type").notNull(),
		targetId: text("target_id").notNull(),
		beforeJson: jsonb("before_json"),
		afterJson: jsonb("after_json"),
		ipAddr: inet("ip_addr"),
		userAgent: text("user_agent"),
	},
	(t) => [
		index("idx_admin_audit_workspace").on(
			t.actorWorkspaceId,
			t.occurredAt.desc(),
		),
		index("idx_admin_audit_target").on(
			t.targetType,
			t.targetId,
			t.occurredAt.desc(),
		),
	],
);

export type AdminAuditLogRow = typeof adminAuditLog.$inferSelect;

// ── Provider keys (BYOK) ──────────────────────────────────────────────────────
// Per-tenant, per-provider upstream API keys (OpenAI sk-…, Anthropic sk-ant-…),
// envelope-encrypted (AES-256-GCM, AAD bound to (tenant_id, provider_id)) before
// storage. Read/written by the gateway BYOK path (crates/gateway/src/db/
// provider_keys.rs, POST /v1/byok/provider-keys). ciphertext_b64 is the base64
// BYOK v2 wire; last4 is display-only. Mirrors migration 08.

export const providerKeys = pgTable(
	"provider_keys",
	{
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		providerId: text("provider_id").notNull(),
		ciphertextB64: text("ciphertext_b64").notNull(),
		last4: text("last4").notNull(),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		updatedAt: timestamp("updated_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [
		primaryKey({ columns: [t.tenantId, t.providerId] }),
		index("provider_keys_tenant_idx").on(t.tenantId),
	],
);

export type ProviderKey = typeof providerKeys.$inferSelect;

// ── Tamper-evident audit ledger ───────────────────────────────────────────────
// `audit_chain_state` persists the per-tenant hash-chain head (seq + prev-hash)
// so the chain survives gateway restarts; `tenant_audit_keys` holds the per-tenant
// Ed25519 signing keypair (BYOK envelope-encrypted) used to sign the ledger /
// Merkle root for Rekor anchoring. Mirror migrations 06 + 03.
// Refs: crates/gateway/src/db/audit_chain_state.rs, crates/gateway/src/audit_keys.rs.

export const auditChainState = pgTable("audit_chain_state", {
	tenantId: uuid("tenant_id")
		.primaryKey()
		.references(() => tenants.id, { onDelete: "cascade" }),
	lastSeq: bigint("last_seq", { mode: "number" }).notNull(),
	// Raw 32-byte SHA-256 of the most recent chain row (bytes end-to-end).
	lastRowHash: bytea("last_row_hash").notNull(),
	updatedAt: timestamp("updated_at", { withTimezone: true })
		.defaultNow()
		.notNull(),
});

export type AuditChainState = typeof auditChainState.$inferSelect;

export const tenantAuditKeys = pgTable(
	"tenant_audit_keys",
	{
		id: uuid("id").defaultRandom().primaryKey(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		// AES-256-GCM envelope-encrypted PKCS#8 DER, base64 (nonce||ct||tag).
		encryptedPrivateKey: text("encrypted_private_key").notNull(),
		// SubjectPublicKeyInfo bytes, base64, for Rekor verification.
		publicKeyB64: text("public_key_b64").notNull().default(""),
		// ADR-062 two-key model: the dedicated ECDSA-P256 anchor keypair used to
		// sign the Rekor v2 hashedrekord entry (pure Ed25519 is rejected by Rekor
		// v2). Nullable — lazily minted on first anchor. Envelope-encrypted under a
		// distinct `anchor-key:` AAD (byok::anchor_key_aad) so it cannot be swapped
		// with the Ed25519 signing key.
		encryptedAnchorKey: text("encrypted_anchor_key"),
		// ECDSA-P256 SubjectPublicKeyInfo (DER), base64 — the Rekor entry verifier
		// pubkey + the verifier's out-of-ClickHouse pin.
		anchorPubkeySpkiB64: text("anchor_pubkey_spki_b64"),
		// Non-null when this key replaced a prior one (rotation trail; self-FK
		// omitted — current gateway is one-key-per-tenant, no rotation yet).
		rotatedFrom: uuid("rotated_from"),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		revokedAt: timestamp("revoked_at", { withTimezone: true }),
	},
	(t) => [uniqueIndex("tenant_audit_keys_one_per_tenant").on(t.tenantId)],
);

export type TenantAuditKey = typeof tenantAuditKeys.$inferSelect;

// ── Payment events (x402 / AP2 / ACP) ─────────────────────────────────────────
// Per-agent payment-protocol span ledger. The gateway records these
// best-effort (crates/gateway/src/payment.rs). Mirrors migration 02.

export const paymentEvents = pgTable(
	"payment_events",
	{
		id: uuid("id").defaultRandom().primaryKey(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		agentId: text("agent_id"),
		traceId: uuid("trace_id"),
		spanId: uuid("span_id"),
		// 'intent' | 'mandate' | 'settled' (enforced by the gateway writer).
		eventType: text("event_type").notNull(),
		amountUsd: numeric("amount_usd", { precision: 20, scale: 8 }),
		recipient: text("recipient"),
		mandateId: text("mandate_id"),
		payload: jsonb("payload"),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [
		index("payment_events_tenant_idx").on(t.tenantId, t.createdAt.desc()),
		index("payment_events_agent_idx").on(
			t.tenantId,
			t.agentId,
			t.createdAt.desc(),
		),
	],
);

export type PaymentEvent = typeof paymentEvents.$inferSelect;

// ── users ────────────────────────────────────────────────────────────
// Provisioned by the gateway WorkOS webhook (user.created / dsync.user.created;
// crates/gateway/src/auth/workos_webhook.rs USER_UPSERT_SQL). Added to schema.ts
// in (2026-07-04) to make Drizzle the single source of truth — it existed
// only in the gateway's writes + the (now-retired) infra SQL. `user_id` is
// supplied by the gateway (a hash of workos_user_id), so there is no default.
// `email` UNIQUE is required by the gateway's `ON CONFLICT (email)` upsert.
export const users = pgTable(
	"users",
	{
		userId: uuid("user_id").primaryKey(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		email: text("email").notNull().unique(),
		workosUserId: text("workos_user_id").unique(),
		name: text("name"),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
	},
	(t) => [index("users_tenant_id_idx").on(t.tenantId)],
);

export type User = typeof users.$inferSelect;

// ── Support requests (in-product "Reach out" widget) ─────────────────────────
// A user's Question / Feedback / Bug message from the dashboard support widget.
// WorkOS ids are stored as TEXT (org + user), NOT a FK to tenants.id — the
// session yields the WorkOS org_id, not the internal tenant UUID, so this
// sidesteps the org→tenant resolution seam (the #1 recurring bug class). Join
// on tenants.workos_org_id downstream if a tenant reference is ever needed.
export const supportRequests = pgTable(
	"support_requests",
	{
		id: uuid("id").defaultRandom().primaryKey(),
		workosOrgId: text("workos_org_id").notNull(),
		workosUserId: text("workos_user_id").notNull(),
		email: text("email"),
		// One of: query | feedback | bug (validated at the route, not a DB enum —
		// a new kind should not need a migration).
		kind: text("kind").notNull(),
		message: text("message").notNull(),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [index("support_requests_created_at_idx").on(t.createdAt)],
);

export type SupportRequest = typeof supportRequests.$inferSelect;

/**
 * B — tool definitions the gateway has actually OBSERVED, pending approval.
 *
 * Deliberately stores NO schema or description text: R3 records the hash, never
 * the tool text, and the observe path must not weaken that. Approving copies the
 * `defHash` the gateway computed at request time, so a client-supplied hash can
 * never become a pin.
 *
 * The primary key includes `defHash`, so a CHANGED definition is a new row
 * rather than an update — the pending list then shows a tool with a second
 * definition, which is the rug-pull signal a tenant needs before approving.
 */
export const observedTools = pgTable(
	"observed_tools",
	{
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		toolName: text("tool_name").notNull(),
		defHash: text("def_hash").notNull(),
		firstSeen: timestamp("first_seen", { withTimezone: true })
			.defaultNow()
			.notNull(),
		lastSeen: timestamp("last_seen", { withTimezone: true })
			.defaultNow()
			.notNull(),
		// Advisory only — incremented per flush, not per request, and under N
		// gateway replicas it under-counts. A "seen a lot" hint for the approve
		// UI; never a billing or quota input.
		seenCount: bigint("seen_count", { mode: "number" }).notNull().default(1),
	},
	(t) => [
		primaryKey({ columns: [t.tenantId, t.toolName, t.defHash] }),
		index("observed_tools_tenant_last_seen_idx").on(t.tenantId, t.lastSeen),
	],
);

export type ObservedTool = typeof observedTools.$inferSelect;

/**
 * Persisted "we already told this tenant" marker for quota notifications
 * (SET-08). Migration `0023_quota_notifications.sql`.
 *
 * The gateway's `QuotaTracker` is process-local and reseeds from ClickHouse on
 * boot, so it cannot answer "have we notified this period?" — a restart
 * moves the counter and takes the answer with it. This table is that answer, and
 * the primary key is the concurrency control: the claim is
 * `INSERT … ON CONFLICT DO NOTHING`, so racing gateway replicas produce exactly
 * one winner with no read-modify-write window.
 *
 * Written ONLY by the gateway. The dashboard does not read it today; it is here
 * because `schema.ts` is canonical for control-plane Postgres (CLAUDE.md §1.5)
 * and a table the gateway writes but Drizzle does not know about is exactly the
 * drift that rule exists to prevent.
 */
export const quotaNotifications = pgTable(
	"quota_notifications",
	{
		tenantId: uuid("tenant_id").notNull(),
		/** Billing period as `YYYYMM` (UTC) — the gateway's `current_year_month()`. */
		period: text("period").notNull(),
		/** `soft_cap` | `hard_cap`. Text, not a PG enum — see the migration header. */
		kind: text("kind").notNull(),
		notifiedAt: timestamp("notified_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [
		primaryKey({ columns: [t.tenantId, t.period, t.kind] }),
		index("quota_notifications_period_idx").on(t.period),
	],
);

export type QuotaNotification = typeof quotaNotifications.$inferSelect;

// ── OBS-18: trace annotations ────────────────────────────────────────────────

/**
 * A human's judgement about one trace: a label, and optionally a note.
 *
 * **The cheapest possible ground truth.** Every later eval and failure-signature
 * feature needs a human verdict to learn from, and today nothing records one.
 *
 * **Why Postgres and not ClickHouse.** Annotations are low-volume, mutable
 * (edited, removed) and read one-trace-at-a-time — the exact opposite of the
 * append-only analytical rows ClickHouse holds. Putting them in ClickHouse would
 * mean a ReplacingMergeTree tombstone dance for what is a single UPDATE here
 * (see the soft-delete/re-create trap). The gateway already owns a Postgres pool.
 *
 * **One annotation per (tenant, trace, span, author)** — the primary key is the
 * concurrency control, so a double-click is `ON CONFLICT DO UPDATE`, not two
 * rows. `span_id` is `''` (not NULL) for a trace-level flag, because NULL is not
 * comparable in a primary key and would silently permit duplicates.
 */
export const traceAnnotations = pgTable(
	"trace_annotations",
	{
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		traceId: text("trace_id").notNull(),
		/** `''` = the whole trace. Never NULL — see the table doc. */
		spanId: text("span_id").notNull().default(""),
		/** `good` | `bad` | `needs_review`. Text, validated in the gateway. */
		label: text("label").notNull(),
		note: text("note").notNull().default(""),
		/** The `sub` claim of whoever flagged it. */
		authorSub: text("author_sub").notNull(),
		/**
		 * EVL-29. NULL = an ad-hoc OBS-18 flag rather than a queue review, so a
		 * trace flagged from the trace header and one reviewed in a queue stay
		 * the SAME row. Deliberately NOT in the primary key — adding it would
		 * re-open the duplicate-row bug the `span_id = ''` sentinel prevents.
		 */
		queueId: uuid("queue_id").references(() => annotationQueues.id),
		/** Answers to the queue's rubric fields, keyed by field `key`. */
		rubricJson: jsonb("rubric_json").notNull().default({}),
		/**
		 * IMMUTABLE SNAPSHOT of the rubric definition this answer was given under
		 * (R224) — the ordered field list, types and options, frozen at submit.
		 * Same class as `dataset_snapshots`: the frozen set is what makes a past
		 * judgement re-readable. A version COUNTER would tell you the rubric
		 * changed; it would not tell you what it SAID, leaving old labels
		 * uninterpretable. `{}` = an ad-hoc OBS-18 flag, answered under no rubric.
		 */
		rubricSnapshot: jsonb("rubric_snapshot").notNull().default({}),
		/**
		 * THE REFERENCE — the whole point of item 12. Production captures input
		 * only (`dataset_routes.rs:35-42`), so a human review is the only source
		 * of an `expected_output` for a trace-derived dataset item.
		 */
		expectedOutput: text("expected_output").notNull().default(""),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		updatedAt: timestamp("updated_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [
		primaryKey({
			columns: [t.tenantId, t.traceId, t.spanId, t.authorSub],
		}),
		// Drives the trace-list "Flagged" filter: which of THIS tenant's traces
		// carry any annotation. Tenant-first so the index is usable by that
		// predicate alone.
		index("trace_annotations_tenant_trace_idx").on(t.tenantId, t.traceId),
		// EVL-29. PARTIAL, on `queue_id IS NOT NULL`: a NULL `queue_id` means
		// an ad-hoc OBS-18 flag rather than a queue review, and those are the
		// majority. Indexing them would grow the index without serving the
		// only query that uses it — "what has been reviewed through queue X".
		index("trace_annotations_queue_idx")
			.on(t.tenantId, t.queueId)
			.where(sql`${t.queueId} IS NOT NULL`),
	],
);

export type TraceAnnotation = typeof traceAnnotations.$inferSelect;

/**
 * EVL-29 — a review queue. **A SAVED FILTER, evaluated at read time** (R221.1),
 * never a materialised member list: a stored membership is a second copy of a
 * judgement that goes stale the moment a threshold moves, and reconciling it
 * against the scores it came from would then be ours to own. Read-time
 * evaluation cannot drift because there is nothing to drift from.
 */
export const annotationQueues = pgTable(
	"annotation_queues",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		name: text("name").notNull(),
		/** The saved filter. Evaluated per read; see the table doc. */
		filterJson: jsonb("filter_json").notNull(),
		/** Ordered list of typed fields — `boolean | choice | text` ONLY (R221.2). */
		rubricJson: jsonb("rubric_json").notNull().default([]),
		/**
		 * REQUIRED (R222). Every review creates a dataset item in the SAME
		 * request, with the reviewer choosing nothing. Nullable-plus-a-picker
		 * would be TWO paths where one is exercised rarely and rots — and "the
		 * loop closes by construction" is only true if the field cannot be absent.
		 */
		defaultDatasetId: uuid("default_dataset_id").notNull(),
		/**
		 * REQUIRED (R223). The `rubric_json` field key whose answer becomes the
		 * item's `expected_output`. A queue that cannot name its reference field
		 * would silently emit items no reference-based scorer can score — the
		 * exact hole item 12 exists to close, reopened by its own tooling.
		 * The validator refuses a `boolean` field here: "true"/"false" as an
		 * expected_output is a scorer comparing against a string that means nothing.
		 */
		expectedOutputField: text("expected_output_field").notNull(),
		createdBy: text("created_by").notNull(),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		updatedAt: timestamp("updated_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		/** Archive, never delete — a review's `queue_id` must not dangle. */
		archivedAt: timestamp("archived_at", { withTimezone: true }),
	},
	(t) => [
		uniqueIndex("annotation_queues_tenant_name_uniq").on(
			t.tenantId,
			sql`lower(${t.name})`,
		),
		// R223, and the CHECK is the half that makes the NOT NULL mean
		// something: `expected_output_field` carries `DEFAULT ''` purely so
		// migration 0033's ADD COLUMN could succeed on the existing empty
		// table, and this constraint is what makes that default UNREACHABLE.
		// Without it the column is nominally required and practically optional.
		check(
			"annotation_queues_expected_field_chk",
			sql`length(${t.expectedOutputField}) > 0`,
		),
		// PARTIAL, on the live set. Every queue list filters to the tenant and
		// archived queues are the minority that nothing lists — indexing them
		// would grow the index without serving the query that uses it.
		index("annotation_queues_tenant_idx")
			.on(t.tenantId)
			.where(sql`${t.archivedAt} IS NULL`),
	],
);

export type AnnotationQueue = typeof annotationQueues.$inferSelect;

// ── DSH-01: in-app notifications ─────────────────────────────────────────────

/**
 * The tenant's inbox — what happened while nobody was looking.
 *
 * **Why it exists.** Alerting today can only leave the building (webhook), so a
 * signal either interrupts someone or is lost. There is nowhere in the product
 * that answers "what happened while I was away".
 *
 * **Read state is TENANT-WIDE, not per-user**, and the UI says so. Per-user read
 * state needs a per-user join that buys little at this scale, and the spec's
 * explicit instruction was "tenant-wide read state, and say so in the UI"
 * rather than a silent half-implementation of per-user.
 *
 * **`link` is a RELATIVE in-app path** (`/slo`, `/billing`), never an absolute
 * URL: a stored absolute URL is an open-redirect waiting to be rendered as an
 * anchor, and this row is written by producers, not by a user.
 */
export const notifications = pgTable(
	"notifications",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		/** `quota` | `alert` | `promotion`. Text, validated in the gateway. */
		kind: text("kind").notNull(),
		title: text("title").notNull(),
		body: text("body").notNull().default(""),
		/** `info` | `warning` | `critical`. */
		severity: text("severity").notNull().default("info"),
		/** Relative in-app path, e.g. `/slo`. Empty = not linkable. */
		link: text("link").notNull().default(""),
		/** NULL = unread. Tenant-wide, per the table doc. */
		readAt: timestamp("read_at", { withTimezone: true }),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [
		// Drives both the unread badge and the panel: newest-first within a
		// tenant, with unread cheaply countable.
		index("notifications_tenant_created_idx").on(t.tenantId, t.createdAt),
	],
);

export type Notification = typeof notifications.$inferSelect;

/**
 * `online_eval_policies` — per-workspace configuration for scoring LIVE traffic
 * with the LLM judge that item 10 already shipped (`EVL-28`, Sprint 3 item 11).
 *
 * ONE POLICY PER WORKSPACE for now (a unique index on `tenant_id`, not a
 * primary key on it, so a second policy is a schema change rather than a data
 * migration if per-prompt policies are ever wanted). The gateway reads this
 * through a cache — never per request.
 *
 * ── THE TWO NUMBERS ARE NOT SYMMETRIC, AND THAT IS THE DESIGN ───────────────
 * `sample_rate` has a founder-set CEILING and a tenant-set value beneath it:
 * coverage is the customer's judgement, but a tenant who sets 100% is spending
 * real money at traffic volume before anyone notices, so the ceiling is ours and
 * it is enforced by a CHECK here rather than only in a handler.
 *
 * `judge_budget_usd_monthly` has NO DEFAULT and is NOT NULL. Creating a policy
 * without naming a cap is a typed 400 at the route, and the column makes it
 * impossible to reach the table without one. **Forcing an explicit money
 * decision beats a silent unlimited** — it is the only shape where a customer
 * cannot be surprised by the first invoice. Do not "helpfully" add a DEFAULT.
 *
 * `sample_salt` exists so sampling is DETERMINISTIC — `hash(salt || trace_id)`
 * against the rate, never a random draw. A customer must be able to say which
 * traces were scored and re-run exactly that set. Per-policy rather than global
 * so two workspaces at the same rate do not score correlated traces.
 */
export const onlineEvalPolicies = pgTable(
	"online_eval_policies",
	{
		id: uuid("id").defaultRandom().primaryKey(),
		tenantId: uuid("tenant_id")
			.notNull()
			.references(() => tenants.id, { onDelete: "cascade" }),
		/** Off without deleting the policy — keeps the cap and salt for when it resumes. */
		enabled: boolean("enabled").notNull().default(true),
		/** `builtin` | `prompt_version` — which of the two rubric sources `rubric` names. */
		rubricKind: text("rubric_kind").notNull(),
		/** A built-in rubric name, or a `prompt_versions.id` the tenant owns. */
		rubric: text("rubric").notNull(),
		/** The grading model. Routed through the tenant's own BYOK, like every judge call. */
		judgeModel: text("judge_model").notNull(),
		/** 0.0–0.10. The ceiling is enforced by a CHECK, not only by a handler. */
		sampleRate: doublePrecision("sample_rate").notNull().default(0.01),
		/** Per-policy salt for deterministic `hash(salt || trace_id)` sampling. */
		sampleSalt: text("sample_salt").notNull(),
		/** REQUIRED. No default, deliberately — see the table doc. */
		judgeBudgetUsdMonthly: doublePrecision(
			"judge_budget_usd_monthly",
		).notNull(),
		createdAt: timestamp("created_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
		updatedAt: timestamp("updated_at", { withTimezone: true })
			.defaultNow()
			.notNull(),
	},
	(t) => [uniqueIndex("online_eval_policies_tenant_uniq").on(t.tenantId)],
);

export type OnlineEvalPolicy = typeof onlineEvalPolicies.$inferSelect;
