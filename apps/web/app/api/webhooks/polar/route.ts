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
 * // pricing-guard: allow "Audit SKU" — stating it is NOT sold
 *      ADD-ON events: none are handled since 2026-09-14 — the Audit SKU is not
 *      sold (B-392); a stray `audit_addon_v1` event is an unknown-key no-op and
 *      NEVER touches the base plan
 * . Per-plan feature flags are NOT set here (those are plan defaults).
 *   6. Unknown plan key / unresolved tenant → log + 200 (no infinite retry).
 *
 * ── ADR-076 / BILL-01 additions, all in the SAME tenants UPDATE as the plan +
 * B-388 clock (never a second statement — a crash between two writes must
 * never leave one applied without the other) ──
 *   - `<plan>_v1` AND `<plan>_v1_year` both resolve to the plan; the interval
 *     sets `tenants.billing_interval`.
 *   - The FIRST paid activation (no `price_protected_until` yet) sets it to
 *     now + `billing_policy.price_protection_months`, and pins
 *     `tenants.price_version` to the CURRENT `pricing_rates.price_version` —
 *     both read from the tables, never literals.
 *   - `subscription.past_due` sets `dunning_started_at = now`; any active
 *     status clears it. The PLAN NEVER CHANGES on past_due — ingest is never
 *     gated on billing state (spec §0.4).
 *   - `.unpaid` / `.revoked` / `.canceled` reaching its end drop the tenant to
 *     `free` and, only when it was PREVIOUSLY paid, set
 *     `data_hold_until = now + billing_policy.dunning_data_hold_days`.
 *
 * E2E is gated on the founder: register the webhook in the Polar dashboard and
 * set POLAR_WEBHOOK_SECRET + POLAR_EXPECTED_ORGANIZATION_ID (+ POLAR_ACCESS_TOKEN)
 * in Vercel.
 */

import { db } from "@/db";
import {
	billingPolicy,
	pricingRates,
	tenants,
	webhookEvents,
	workspaceEntitlements,
} from "@/db/schema";
import type { AnnualPairJson } from "@/db/schema";
import {
	sendDroppedToFreeEmail,
	sendDunningStartedEmail,
	sendPlanChangedEmail,
} from "@/lib/email";
import {
	type BillingInterval,
	type PairHalf,
	type PlanResolution,
	decodeWebhookSecret,
	eventClock,
	isActiveStatus,
	isPastDueStatus,
	isStale,
	logSafe,
	planForLookupKey,
	resolvePair,
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
	let event: {
		type: string;
		timestamp?: unknown;
		data: Record<string, unknown>;
	};
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
	timestamp?: unknown;
	data: Record<string, unknown>;
}): Promise<void> {
	if (event.type.startsWith("subscription.")) {
		await handleSubscriptionChange(
			event.type,
			event.data,
			eventClock(event.data, event.timestamp),
		);
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

/**
 * `billing_policy.value` for `price_protection_months` / `dunning_data_hold_days`
 * is stored as `jsonb` — a bare number (`12`, `30`). Reference-tables rule:
 * never a literal fallback baked into behaviour, only a defensive "policy row
 * missing" case that fails toward the SHORTER (customer-safe) side rather than
 * silently granting an unbounded promise.
 */
async function readPolicyNumber(key: string): Promise<number | null> {
	const [row] = await db
		.select({ value: billingPolicy.value })
		.from(billingPolicy)
		.where(eq(billingPolicy.key, key))
		.limit(1);
	if (!row) return null;
	const v = row.value;
	return typeof v === "number" ? v : null;
}

/** `billing_policy.dunning_retry_days` is stored as a jsonb array, e.g. `[1,5,14]`. */
async function readPolicyDayArray(key: string): Promise<number[]> {
	const [row] = await db
		.select({ value: billingPolicy.value })
		.from(billingPolicy)
		.where(eq(billingPolicy.key, key))
		.limit(1);
	const v = row?.value;
	return Array.isArray(v) && v.every((n) => typeof n === "number") ? v : [];
}

/** The `pricing_rates.price_version` currently marked `is_current`. */
async function readCurrentPriceVersion(): Promise<string | null> {
	const [row] = await db
		.select({ priceVersion: pricingRates.priceVersion })
		.from(pricingRates)
		.where(eq(pricingRates.isCurrent, true))
		.limit(1);
	return row?.priceVersion ?? null;
}

function addMonths(d: Date, months: number): Date {
	const out = new Date(d);
	out.setUTCMonth(out.getUTCMonth() + months);
	return out;
}

/** A Polar ISO-8601 timestamp field, or null when absent / not a string / unparsable. */
function parseIsoDate(v: unknown): Date | null {
	if (typeof v !== "string") return null;
	const d = new Date(v);
	return Number.isNaN(d.getTime()) ? null : d;
}

function addDays(d: Date, days: number): Date {
	return new Date(d.getTime() + days * 24 * 60 * 60 * 1000);
}

async function handleSubscriptionChange(
	eventType: string,
	data: Record<string, unknown>,
	// B-388: the event's own clock (Polar `modified_at`, else the envelope
	// timestamp); `null` = unparsable, which APPLIES.
	eventAt: Date | null,
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

	// B-388: refuse an event OLDER than the last one applied to this tenant.
	// Acked (200), not applied, logged with both clocks — a stale retry after a
	// cancellation must not re-activate the plan. Compared per TENANT, not per
	// subscription id: a plan cannot go backwards in time whichever subscription
	// object carries the older clock.
	if (isStale(tenant.polarSubscriptionModifiedAt, eventAt)) {
		console.warn(
			"[polar-webhook] STALE subscription event — acked, NOT applied:",
			logSafe(eventType),
			"event",
			eventAt?.toISOString() ?? "unparsable",
			"< applied",
			tenant.polarSubscriptionModifiedAt?.toISOString(),
		);
		return;
	}

	// ── BILL-02 (founder ruling B14 → option (c)): an ANNUAL tenant holds TWO
	// Polar subscriptions. Any event for a `_base_year` / `_usage_month` key —
	// and a MONTHLY key arriving for a tenant that already holds a pair (P6) —
	// goes through the pair resolver, which serves the tier only when both
	// halves are held on the same plan and REFUSES every half-state to Free
	// with a named alert (spec §2.4). It never calls Polar: the other half's
	// last-seen state is in `tenants.annual_pair`.
	const keyed = planForLookupKey(lookupKey);
	const half = keyed?.half ?? null;
	const heldPair = tenant.annualPair ?? null;
	const holdsPair = !!(heldPair?.base || heldPair?.usage);
	if (half === "base" || half === "usage" || (holdsPair && half === "single")) {
		await applyPairEvent({
			tenant,
			subId,
			customerId,
			status,
			half: half as "base" | "usage" | "single",
			keyedPlan: keyed?.plan ?? null,
			data,
			eventAt,
		});
		return;
	}

	// `free` is now a valid tenants.plan value, so cancellation sets it
	// explicitly (was previously left stale because the enum had no `free`).
	const planValue = resolution.kind === "free" ? "free" : resolution.planEnum;
	const interval: BillingInterval | null =
		resolution.kind === "plan" ? resolution.interval : null;
	const now = new Date();

	// ── ADR-076 / BILL-01, §0.5 billing mechanics — ALL of these land in the
	// SAME statement as the plan + clock below (B-388's ordering guard: a crash
	// between two writes must never leave the plan applied with a stale clock,
	// and the same now holds for price protection / dunning / data-hold). ──
	const extra: Record<string, unknown> = {};

	if (interval) extra.billingInterval = interval;
	// B-410: the subscription cycle, straight from the payload. The dashboard
	// rates usage over this window so it agrees with the invoice; a drop to
	// Free clears it and the usage route falls back to the calendar month.
	const periodStart = parseIsoDate(data.current_period_start);
	const periodEnd = parseIsoDate(data.current_period_end);
	if (planValue === "free") {
		extra.currentPeriodStart = null;
		extra.currentPeriodEnd = null;
	} else if (periodStart && periodEnd) {
		extra.currentPeriodStart = periodStart;
		extra.currentPeriodEnd = periodEnd;
	}

	// Dunning: past_due starts the clock; any active status clears it. Plan is
	// UNCHANGED either way — `resolvePlan` never resolves `past_due` to `free`,
	// so ingest is never gated on billing state (spec §0.4).
	if (isPastDueStatus(status)) {
		extra.dunningStartedAt = now;
	} else if (isActiveStatus(status)) {
		extra.dunningStartedAt = null;
	}

	// Drop-to-Free from a previously PAID plan: hold the data per
	// `billing_policy.dunning_data_hold_days`, read from the table — never a
	// literal (`.claude/rules/reference-tables.md`). Re-cancelling an
	// already-Free tenant does not re-arm the hold clock.
	if (planValue === "free" && tenant.plan && tenant.plan !== "free") {
		const holdDays = await readPolicyNumber("dunning_data_hold_days");
		if (holdDays !== null) extra.dataHoldUntil = addDays(now, holdDays);
	}

	// First paid activation: price protection pins BOTH the expiry and the
	// rate version, both read from the DB, never a literal. Gated on
	// `priceProtectedUntil` being unset rather than on the specific event type
	// — the property that matters is "this tenant has never been price
	// -protected before", however that transition arrived.
	if (planValue !== "free" && !tenant.priceProtectedUntil) {
		const months = await readPolicyNumber("price_protection_months");
		const version = await readCurrentPriceVersion();
		if (months !== null) extra.priceProtectedUntil = addMonths(now, months);
		if (version) extra.priceVersion = version;
	}

	await db
		.update(tenants)
		.set({
			plan: planValue,
			...(customerId ? { polarCustomerId: customerId } : {}),
			polarSubscriptionId: resolution.kind === "free" ? null : subId,
			// The clock is set in the SAME statement as the plan, so a crash
			// between the two cannot leave a plan applied with no clock.
			...(eventAt ? { polarSubscriptionModifiedAt: eventAt } : {}),
			...extra,
			updatedAt: now,
		})
		.where(eq(tenants.id, tenant.id));

	// Polar = plan membership only: set plan_lookup_key, never per-feature flags
	// (those are workspace overrides under deny-overrides-grant). onConflict sets
	// ONLY plan_lookup_key, so a per-workspace `f_audit_addon` override (the Enterprise export grant)
	// survives a plan change.
	await db
		.insert(workspaceEntitlements)
		.values({ tenantId: tenant.id, planLookupKey: resolution.lookupKey })
		.onConflictDoUpdate({
			target: workspaceEntitlements.tenantId,
			set: { planLookupKey: resolution.lookupKey, updatedAt: new Date() },
		});

	// ── item 8: transactional emails, fire-and-forget-safe (sendEmail never
	// throws) — sent AFTER the state write succeeds, never before, and gated on
	// an ACTUAL transition (never re-sent on a same-state retry delivery). No
	// billingEmail on file is a silent no-op, not a failure.
	if (tenant.billingEmail) {
		if (isPastDueStatus(status) && !tenant.dunningStartedAt) {
			const retryDays = await readPolicyDayArray("dunning_retry_days");
			await sendDunningStartedEmail(tenant.billingEmail, {
				plan: tenant.plan ?? planValue,
				retryDays,
			});
		} else if (planValue === "free" && tenant.plan && tenant.plan !== "free") {
			await sendDroppedToFreeEmail(tenant.billingEmail, {
				previousPlan: tenant.plan,
				dataHoldUntil: (extra.dataHoldUntil as Date | undefined) ?? now,
			});
		} else if (tenant.plan && tenant.plan !== planValue) {
			await sendPlanChangedEmail(tenant.billingEmail, {
				fromPlan: tenant.plan,
				toPlan: planValue,
			});
		}
	}
}

/**
 * BILL-02 §2.4 — merge one half's event into the stored pair, resolve, and
 * write the WHOLE billing state in ONE statement (B-388's ordering guard
 * holds: plan + clock + period + ids + alert land together or not at all).
 */
async function applyPairEvent(args: {
	tenant: NonNullable<Awaited<ReturnType<typeof correlateTenant>>>;
	subId: string | null;
	customerId: string | null;
	status: string | null;
	half: "base" | "usage" | "single";
	keyedPlan: string | null;
	data: Record<string, unknown>;
	eventAt: Date | null;
}): Promise<void> {
	const { tenant, subId, customerId, status, half, keyedPlan, data, eventAt } =
		args;
	const now = new Date();
	const pair: AnnualPairJson = { ...(tenant.annualPair ?? {}) };

	let alert: string | null = null;
	let planValue: "free" | "builder" | "team" | "business" | "enterprise";
	let periodStart: Date | null = null;
	let periodEnd: Date | null = null;
	let pastDue = false;

	if (half === "single") {
		// P6: a monthly subscription for a tenant that holds an annual pair —
		// two live shapes for one tenant is never valid. Refuse, keep the pair as
		// evidence; repair is a support action, never automatic.
		alert = "annual_pair_mismatch";
		planValue = "free";
	} else {
		const incoming: PairHalf = {
			id: subId ?? pair[half]?.id ?? "",
			plan: keyedPlan ?? pair[half]?.plan ?? "",
			status: status ?? "",
			period_start:
				typeof data.current_period_start === "string"
					? data.current_period_start
					: (pair[half]?.period_start ?? null),
			period_end:
				typeof data.current_period_end === "string"
					? data.current_period_end
					: (pair[half]?.period_end ?? null),
		};
		pair[half] = incoming;
		const res = resolvePair(pair);
		if (res.kind === "annual") {
			planValue = res.planEnum;
			periodStart = parseIsoDate(res.periodStart);
			periodEnd = parseIsoDate(res.periodEnd);
			pastDue = res.pastDue === true;
		} else if (res.kind === "refuse") {
			alert = res.reason;
			planValue = "free";
		} else {
			// neither half held: the ordinary drop to Free
			planValue = "free";
		}
	}
	pair.alert = alert;

	const extra: Record<string, unknown> = {};
	if (planValue === "free") {
		extra.currentPeriodStart = null;
		extra.currentPeriodEnd = null;
	} else {
		extra.currentPeriodStart = periodStart;
		extra.currentPeriodEnd = periodEnd;
	}
	extra.dunningStartedAt = pastDue ? (tenant.dunningStartedAt ?? now) : null;
	if (planValue === "free" && tenant.plan && tenant.plan !== "free") {
		const holdDays = await readPolicyNumber("dunning_data_hold_days");
		if (holdDays !== null) extra.dataHoldUntil = addDays(now, holdDays);
	}
	if (planValue !== "free" && !tenant.priceProtectedUntil) {
		const months = await readPolicyNumber("price_protection_months");
		const version = await readCurrentPriceVersion();
		if (months !== null) extra.priceProtectedUntil = addMonths(now, months);
		if (version) extra.priceVersion = version;
	}

	await db
		.update(tenants)
		.set({
			plan: planValue,
			billingInterval: "year",
			...(customerId ? { polarCustomerId: customerId } : {}),
			// An annual tenant never has a "single" subscription id.
			polarSubscriptionId: null,
			polarBaseSubscriptionId: pair.base?.id ?? null,
			polarUsageSubscriptionId: pair.usage?.id ?? null,
			annualPair: pair,
			...(eventAt ? { polarSubscriptionModifiedAt: eventAt } : {}),
			...extra,
			updatedAt: now,
		})
		.where(eq(tenants.id, tenant.id));

	const lookupKey = planValue === "free" ? "free_v1" : `${planValue}_v1`;
	await db
		.insert(workspaceEntitlements)
		.values({ tenantId: tenant.id, planLookupKey: lookupKey })
		.onConflictDoUpdate({
			target: workspaceEntitlements.tenantId,
			set: { planLookupKey: lookupKey, updatedAt: new Date() },
		});

	if (alert) {
		console.warn(
			"[polar-webhook] BILL-02 annual pair REFUSED — plan set to free:",
			logSafe(alert),
			"tenant",
			logSafe(tenant.id),
			"half",
			logSafe(half),
		);
	}

	if (tenant.billingEmail) {
		if (planValue === "free" && tenant.plan && tenant.plan !== "free") {
			await sendDroppedToFreeEmail(tenant.billingEmail, {
				previousPlan: tenant.plan,
				dataHoldUntil: (extra.dataHoldUntil as Date | undefined) ?? now,
			});
		} else if (tenant.plan && tenant.plan !== planValue) {
			await sendPlanChangedEmail(tenant.billingEmail, {
				fromPlan: tenant.plan,
				toPlan: planValue,
			});
		}
	}
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
async function correlateTenant(data: Record<string, unknown>): Promise<{
	id: string;
	plan: string | null;
	polarSubscriptionModifiedAt: Date | null;
	priceProtectedUntil: Date | null;
	billingEmail: string | null;
	dunningStartedAt: Date | null;
	annualPair: AnnualPairJson | null;
} | null> {
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
		.select({
			id: tenants.id,
			plan: tenants.plan,
			polarSubscriptionModifiedAt: tenants.polarSubscriptionModifiedAt,
			priceProtectedUntil: tenants.priceProtectedUntil,
			billingEmail: tenants.billingEmail,
			dunningStartedAt: tenants.dunningStartedAt,
			annualPair: tenants.annualPair,
		})
		.from(tenants)
		.where(
			tenantExternalId
				? eq(tenants.id, tenantExternalId)
				: eq(tenants.polarCustomerId, customerId as string),
		)
		.limit(1);
	return row ?? null;
}
