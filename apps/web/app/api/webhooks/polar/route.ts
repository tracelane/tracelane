/**
 * POST /api/webhooks/polar — Polar.sh subscription/order webhook.
 *
 * Pipeline (mirrors crates/gateway/src/billing/webhook.rs):
 *   1. 503 if POLAR_WEBHOOK_SECRET unset — never accept unsigned events.
 *   2. Standard Webhooks signature verification (401 on failure).
 *   3. organization_id cross-check vs POLAR_EXPECTED_ORGANIZATION_ID (503 if
 *      that env is unset, 401 on mismatch). Bypass in non-prod only.
 *   4. Idempotency: dedup on (source='polar', webhook-id header) BEFORE
 *      dispatch; record AFTER successful dispatch (at-least-once > at-most-once).
 *      Polar's envelope carries no top-level id — the delivery id is the header.
 *   5. Dispatch subscription.* → BASE plan events update tenants (plan,
 *      polar_customer_id, polar_subscription_id) + upsert
 *      workspace_entitlements.plan_lookup_key (plan membership only).
 *      ADD-ON events (a separate Polar subscription — the $999 Audit SKU) grant
 *      the matching workspace_entitlements boolean and NEVER touch the base plan
 * . Per-plan feature flags are NOT set here (those are plan defaults).
 *   6. Unknown plan key / unresolved tenant → log + 200 (no infinite retry).
 *
 * E2E is gated on the founder: register the webhook in the Polar dashboard and
 * set POLAR_WEBHOOK_SECRET + POLAR_EXPECTED_ORGANIZATION_ID (+ POLAR_ACCESS_TOKEN)
 * in Vercel.
 */

import { db } from "@/db";
import { tenants, webhookEvents, workspaceEntitlements } from "@/db/schema";
import {
	type PlanResolution,
	decodeWebhookSecret,
	isAddOnLookupKey,
	logSafe,
	resolvePlan,
	verifySignature,
} from "@/lib/polar-webhook";
import { and, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const SOURCE = "polar";

function orgCheckBypassed(): boolean {
	return (
		process.env.NODE_ENV !== "production" &&
		process.env.TRACELANE_POLAR_TEST_NO_ORG_CHECK === "1"
	);
}

function extractOrganizationId(data: Record<string, unknown>): string | null {
	// Org-scoped events carry a top-level organization_id.
	const top = data.organization_id;
	if (typeof top === "string") return top;
	// Subscription/order events do NOT — the org id lives on the nested
	// `product` (Polar's Subscription has no top-level organization_id).
	const product = data.product as Record<string, unknown> | undefined;
	if (product && typeof product.organization_id === "string")
		return product.organization_id;
	const sub = data.subscription as Record<string, unknown> | undefined;
	if (sub && typeof sub.organization_id === "string")
		return sub.organization_id;
	return null;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
	const rawSecret = process.env.POLAR_WEBHOOK_SECRET;
	if (!rawSecret) {
		// Not configured yet — fail closed, never accept unsigned events.
		return NextResponse.json(
			{ error: "webhook not configured" },
			{ status: 503 },
		);
	}

	const webhookId = request.headers.get("webhook-id");
	const webhookTimestamp = request.headers.get("webhook-timestamp");
	const signatureHeader = request.headers.get("webhook-signature");
	if (!webhookId || !webhookTimestamp || !signatureHeader) {
		return NextResponse.json(
			{ error: "missing Standard Webhooks headers" },
			{ status: 400 },
		);
	}

	// Raw body is required for the HMAC — read it once, parse JSON from the
	// same bytes.
	const body = await request.text();

	const verify = verifySignature({
		webhookId,
		webhookTimestamp,
		signatureHeader,
		body,
		secret: decodeWebhookSecret(rawSecret),
		nowUnix: Math.floor(Date.now() / 1000),
	});
	if (!verify.ok) {
		console.warn(
			"[polar-webhook] signature verification failed:",
			verify.reason,
		);
		return NextResponse.json({ error: "invalid signature" }, { status: 401 });
	}

	// Polar's Standard Webhooks envelope is `{ type, timestamp, data }`: the
	// unique delivery id is the `webhook-id` HEADER, not a body field, so we do
	// NOT require a top-level `id`. Idempotency keys on `webhookId` (below).
	let event: { type: string; data: Record<string, unknown> };
	try {
		event = JSON.parse(body);
	} catch {
		return NextResponse.json(
			{ error: "malformed event JSON" },
			{ status: 400 },
		);
	}
	if (!event?.type || typeof event.data !== "object" || event.data === null) {
		return NextResponse.json(
			{ error: "malformed event shape" },
			{ status: 400 },
		);
	}

	// organization_id cross-check (symmetric).
	if (!orgCheckBypassed()) {
		// `.trim()` is REQUIRED: `wrangler secret put` / `echo` can append a
		// trailing newline to the stored value, and a clean `actual` (parsed from
		// JSON) would then never equal `"<uuid>\n"` — a silent 401 storm. The
		// secret path already trims (`decodeWebhookSecret`); this makes the org
		// check symmetric.
		const expected = process.env.POLAR_EXPECTED_ORGANIZATION_ID?.trim();
		if (!expected) {
			console.error("[polar-webhook] POLAR_EXPECTED_ORGANIZATION_ID unset");
			return NextResponse.json(
				{ error: "organization cross-check not configured" },
				{ status: 503 },
			);
		}
		// An org id is a public identifier, not a credential — log actual vs
		// expected on mismatch so a config error is diagnosable (an unlogged
		// mismatch left blind through several redeliver cycles).
		const actual = extractOrganizationId(event.data);
		if (actual !== expected) {
			console.warn(
				`[polar-webhook] organization_id mismatch — refusing (expected=${expected} actual=${logSafe(actual)})`,
			);
			return NextResponse.json(
				{ error: "organization_id mismatch" },
				{ status: 401 },
			);
		}
	}

	// Idempotency: has this event already been processed?
	const seen = await db
		.select({ eventId: webhookEvents.eventId })
		.from(webhookEvents)
		.where(
			and(
				eq(webhookEvents.source, SOURCE),
				eq(webhookEvents.eventId, webhookId),
			),
		)
		.limit(1);
	if (seen[0]) {
		return NextResponse.json({ ok: true, duplicate: true }, { status: 200 });
	}

	try {
		await dispatch(event);
	} catch (err) {
		// Surface as 503 so Polar retries; the event is NOT recorded.
		console.error("[polar-webhook] dispatch failed:", err);
		return NextResponse.json({ error: "dispatch failed" }, { status: 503 });
	}

	// Record AFTER successful dispatch (ON CONFLICT DO NOTHING).
	await db
		.insert(webhookEvents)
		.values({ source: SOURCE, eventId: webhookId })
		.onConflictDoNothing({
			target: [webhookEvents.source, webhookEvents.eventId],
		});

	return NextResponse.json({ ok: true }, { status: 200 });
}

async function dispatch(event: {
	type: string;
	data: Record<string, unknown>;
}): Promise<void> {
	if (event.type.startsWith("subscription.")) {
		await handleSubscriptionChange(event.type, event.data);
		return;
	}
	if (event.type.startsWith("order.")) {
		console.info(
			"[polar-webhook] order event (no action in V1):",
			logSafe(event.type),
		);
		return;
	}
	// Unhandled event types are acked (recorded) without action.
}

async function handleSubscriptionChange(
	eventType: string,
	data: Record<string, unknown>,
): Promise<void> {
	const subId = typeof data.id === "string" ? data.id : null;
	const customerId =
		typeof data.customer_id === "string" ? data.customer_id : null;
	const status = typeof data.status === "string" ? data.status : null;

	const product = data.product as
		| { metadata?: Record<string, unknown> }
		| undefined;
	// Polar product metadata key is `lookup_key` (set in the Polar dashboard
	// May 2026), not `tracelane_plan_key`.
	const lookupKeyVal = product?.metadata?.lookup_key;
	const lookupKey = typeof lookupKeyVal === "string" ? lookupKeyVal : null;

	// Add-on subscriptions (the $999 Audit SKU, seat/overage meters, HIPAA-GCP)
	// are a SEPARATE Polar subscription from the base plan. Route them BEFORE the
	// plan resolver — which would otherwise class every add-on as "unknown" and
	// no-op — so a real Audit-SKU purchase actually flips f_audit_addon.
	// They must never touch tenants.plan / polar_subscription_id.
	if (isAddOnLookupKey(lookupKey)) {
		await handleAddOnChange(eventType, data, lookupKey as string, status);
		return;
	}

	const resolution: PlanResolution = resolvePlan({
		eventType,
		status,
		lookupKey,
	});

	if (resolution.kind === "unknown") {
		// Genuinely unknown key (add-ons are handled above) — ack, no plan change.
		console.warn(
			"[polar-webhook] unknown lookup_key — acked, no plan change:",
			logSafe(resolution.rawKey),
		);
		return;
	}

	// Correlate the tenant (external_id = our tenant UUID; polar_customer_id
	// fallback). Null ⇒ ack (no retry loop).
	const tenant = await correlateTenant(data);
	if (!tenant) {
		const customer = data.customer as { external_id?: unknown } | undefined;
		console.warn(
			"[polar-webhook] no tenant for subscription — acked:",
			logSafe(
				(typeof customer?.external_id === "string"
					? customer.external_id
					: null) ?? customerId,
			),
		);
		return;
	}

	// `free` is now a valid tenants.plan value, so cancellation sets it
	// explicitly (was previously left stale because the enum had no `free`).
	const planValue = resolution.kind === "free" ? "free" : resolution.planEnum;
	await db
		.update(tenants)
		.set({
			plan: planValue,
			...(customerId ? { polarCustomerId: customerId } : {}),
			polarSubscriptionId: resolution.kind === "free" ? null : subId,
			updatedAt: new Date(),
		})
		.where(eq(tenants.id, tenant.id));

	// Polar = plan membership only: set plan_lookup_key, never per-feature flags
	// (those are workspace overrides under deny-overrides-grant). onConflict sets
	// ONLY plan_lookup_key, so a previously-granted add-on flag (f_audit_addon)
	// survives a plan change.
	await db
		.insert(workspaceEntitlements)
		.values({ tenantId: tenant.id, planLookupKey: resolution.lookupKey })
		.onConflictDoUpdate({
			target: workspaceEntitlements.tenantId,
			set: { planLookupKey: resolution.lookupKey, updatedAt: new Date() },
		});
}

/**
 * Correlate the tenant for a subscription/add-on event. The gateway sets the
 * Polar customer `external_id` to the internal tenant UUID
 * (crates/gateway/src/billing/polar_client.rs); fall back to an existing
 * `polar_customer_id` mapping. A non-UUID external_id is treated as absent — it
 * can never match a tenants.id row, and unvalidated it produces a driver-level
 * error → 5xx → Polar retry loop. Returns the tenant row (id + current plan) or
 * null (the caller acks 200).
 */
async function correlateTenant(
	data: Record<string, unknown>,
): Promise<{ id: string; plan: string | null } | null> {
	const customerId =
		typeof data.customer_id === "string" ? data.customer_id : null;
	const customer = data.customer as { external_id?: unknown } | undefined;
	const UUID_RE =
		/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	const tenantExternalId =
		typeof customer?.external_id === "string" &&
		UUID_RE.test(customer.external_id)
			? customer.external_id
			: null;
	if (!tenantExternalId && !customerId) return null;
	const [row] = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(
			tenantExternalId
				? eq(tenants.id, tenantExternalId)
				: eq(tenants.polarCustomerId, customerId as string),
		)
		.limit(1);
	return row ?? null;
}

/**
 * Apply an add-on subscription (a SEPARATE Polar subscription from the base
 * plan). Only add-ons with a WIRED boolean grant mutate state — currently the
 * $999 Audit SKU (`audit_addon_v1` → `workspace_entitlements.f_audit_addon`),
 * which unlocks the Article-12 evidence-pack export + Compliance Handbook and
 * forces full-capture (see `lib/entitlements.ts`). Everything else (overage /
 * seat meters — metered, not a boolean; HIPAA-GCP — needs a manual BAA + GCP
 * deploy, never an auto-flip) is logged LOUDLY for manual handling and leaves
 * state unchanged.
 *
 * NEVER touches `tenants.plan` / `polar_subscription_id` — those belong to the
 * base plan's own subscription. Cancellation of the add-on (canceled/revoked)
 * sets the grant FALSE, so a churned Audit SKU actually re-locks the export.
 *
 * The upsert preserves the tenant's real `plan_lookup_key`: on CONFLICT it sets
 * ONLY `f_audit_addon`; on INSERT (no row yet) `plan_lookup_key` is derived from
 * the tenant's current plan (the column is NOT NULL + FK to plan_entitlements).
 */
async function handleAddOnChange(
	eventType: string,
	data: Record<string, unknown>,
	lookupKey: string,
	status: string | null,
): Promise<void> {
	if (lookupKey !== "audit_addon_v1") {
		// Known add-on, but its grant is not a simple auto-flippable boolean.
		console.error(
			`[polar-webhook] add-on ${lookupKey} purchased — grant NOT auto-wired (metered, or needs manual ops e.g. HIPAA BAA + GCP deploy). State unchanged; may need manual handling.`,
		);
		return;
	}

	const tenant = await correlateTenant(data);
	if (!tenant) {
		console.warn(
			`[polar-webhook] audit add-on: no tenant correlation — acked (${lookupKey})`,
		);
		return;
	}

	const canceled =
		/canceled|revoked/.test(eventType) ||
		status === "canceled" ||
		status === "revoked";
	const active = !canceled;
	// plan_lookup_key is NOT NULL + FK; on INSERT derive it from the current plan.
	const planKey = `${tenant.plan ?? "free"}_v1`;

	await db
		.insert(workspaceEntitlements)
		.values({
			tenantId: tenant.id,
			planLookupKey: planKey,
			fAuditAddon: active,
		})
		.onConflictDoUpdate({
			target: workspaceEntitlements.tenantId,
			set: { fAuditAddon: active, updatedAt: new Date() },
		});

	console.info(
		`[polar-webhook] audit add-on ${active ? "GRANTED" : "REVOKED"} (f_audit_addon=${active}) for tenant ${tenant.id}`,
	);
}
