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
	index,
	doublePrecision,
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
		// dropped it from the gateway (WorkOS owns org names — the gateway never
		// reads it), but `drizzle-kit push` never dropped the column, so it
		// persists. Keeping it here is the honest, non-destructive reconcile.
		name: text("name"),
	},
	(t) => [
		uniqueIndex("tenants_workos_org_id_idx").on(t.workosOrgId),
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
	fHipaaGcpAddon: boolean("f_hipaa_gcp_addon").notNull().default(false),
	fAuditAddon: boolean("f_audit_addon").notNull().default(false),
	// ADR-048 D2: full-capture gate. Business + Enterprise base = TRUE; others
	// FALSE. Audit-SKU-active forces full regardless (resolved in entitlements).
	fFullCapture: boolean("f_full_capture").notNull().default(false),
	// observe). Team+ = TRUE (seeded); Builder is read-only, Free none.
	fPromptPromotionWrite: boolean("f_prompt_promotion_write")
		.notNull()
		.default(false),
	// User-facing alerting (ADR-059; migration 0012). DARK on every plan until the
	// founder flips it at DoD close; a per-tenant workspace override grants early.
	fAlerts: boolean("f_alerts").notNull().default(false),
	// Inline guardrail V1 rails (infra migration 12 → reconciled into Drizzle in
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
		fPromptPromotionWrite: boolean("f_prompt_promotion_write"),
		// ADR-059 alerting override (NULL = inherit plan).
		fAlerts: boolean("f_alerts"),
		// Per-tenant guardrail-rail overrides (NULL = inherit plan). infra
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
	},
	(t) => [
		index("api_keys_tenant_id_idx").on(t.tenantId),
		uniqueIndex("api_keys_lookup_hash_idx").on(t.lookupHash),
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

// Provisioned by the gateway WorkOS webhook (user.created / dsync.user.created;
// crates/gateway/src/auth/workos_webhook.rs USER_UPSERT_SQL). Added to schema.ts
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
