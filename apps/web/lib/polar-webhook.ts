/**
 * Polar.sh webhook helpers — Standard Webhooks signature verification and
 * plan-key resolution. Pure functions, no I/O, so they unit-test without a DB.
 *
 * Mirrors the gateway handler (`crates/gateway/src/billing/webhook.rs`):
 *   - signed payload = `${webhook_id}.${webhook_timestamp}.${body}`
 *   - HMAC-SHA256, base64; header is `v1,<b64>` (space-separated during a
 *     secret-rotation window).
 *   - Polar's secret is `polar_whs_<…>`; the HMAC key is the raw UTF-8 bytes of
 *     the ENTIRE secret string (prefix included) — NOT base64-decoded. Polar's
 *     own `validateEvent` does `base64(utf8(secret))` and `standardwebhooks`
 *     base64-decodes that back, so the two transforms cancel to `utf8(secret)`.
 *   - 5-minute timestamp tolerance (replay protection).
 *
 * Plan mapping uses the CURRENT unprefixed lookup keys per `.claude/rules/
 * billing.md` (`builder_v1` … not the gateway's stale `tracelane_builder_v1`).
 */

import crypto from "node:crypto";

/** Standard Webhooks replay tolerance (seconds). */
export const TOLERANCE_SECONDS = 300;
const MAX_V1_SIGS = 8;

/**
 * Derive the HMAC key from a Polar webhook secret.
 *
 * This is NOT the vanilla Standard Webhooks convention. Polar's secret is
 * `polar_whs_<…>` and its SDK keys the HMAC with the raw UTF-8 bytes of the
 * *entire* secret string (prefix included): `@polar-sh/sdk` `validateEvent`
 * computes `base64(utf8(secret))` and the `standardwebhooks` `Webhook` ctor
 * base64-decodes that back (the value never starts with `whsec_`), so the two
 * transforms cancel to `utf8(secret)`. Hence: no prefix strip, no base64
 * decode — just the raw bytes. `.trim()` guards against an accidental trailing
 * newline in the env var; a real Polar secret carries no surrounding whitespace.
 */
export function decodeWebhookSecret(raw: string): Buffer {
	return Buffer.from(raw.trim(), "utf-8");
}

/**
 * Make a webhook-supplied value safe to interpolate into a log line.
 *
 * Every call site sits AFTER HMAC signature verification, so the value is
 * Polar-authenticated — but Polar relays fields a *customer* controls (product
 * lookup keys, `external_id`), and a CR/LF in one of those forges a complete,
 * convincing extra entry in a line-oriented log stream (CodeQL js/log-injection,
 * 4 alerts on the public mirror). Strips CR, LF and the other C0 controls, and
 * caps length so one long field cannot push the real entry out of view.
 *
 * @param v - untrusted value of any shape. Non-strings render as their type
 *            name (`null` as `"null"`) rather than being coerced.
 * @returns a single-line string of at most 200 chars, safe as a log field.
 *
 * @example
 * logSafe("ok");                       // "ok"
 * logSafe("a\nWARN forged");           // "a\ufffdWARN forged"  (one line)
 * logSafe(null);                       // "null"
 */
export function logSafe(v: unknown): string {
	if (typeof v !== "string") return v === null ? "null" : typeof v;
	return (
		v
			// CR/LF is split out from the C0 range below because it names the actual
			// attack: a newline in a Polar-relayed, customer-controlled field forges a
			// whole extra log entry. The range would cover it either way.
			// NOTE: CodeQL's js/log-injection sanitiser does not recognise this
			// function in EITHER form (character class or explicit split) — verified
			// against real scans of both. The alerts are dismissed with that reason
			// rather than reshaping a provably-correct sanitiser to match a tool
			// model; `logSafe` is covered by tests in polar-webhook.test.ts.
			.replace(/[\r\n]/g, "\ufffd")
			// Remaining C0 controls (ESC — terminal escape sequences — and DEL).
			// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping C0 controls is the point
			.replace(/[\u0000-\u001f\u007f]/g, "\ufffd")
			.slice(0, 200)
	);
}

export type VerifyResult = { ok: true } | { ok: false; reason: string };

/** Parse the `webhook-signature` header into its `v1,` entries (bounded). */
function parseV1Sigs(header: string): string[] {
	const out: string[] = [];
	for (const part of header.split(" ")) {
		const p = part.trim();
		if (!p) continue;
		const idx = p.indexOf(",");
		if (idx === -1) continue;
		if (p.slice(0, idx) === "v1") {
			const sig = p.slice(idx + 1);
			if (sig.length > 256) continue;
			out.push(sig);
			if (out.length >= MAX_V1_SIGS) break;
		}
	}
	return out;
}

function timingSafeStrEqual(a: string, b: string): boolean {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	if (ab.length !== bb.length) return false;
	return crypto.timingSafeEqual(ab, bb);
}

/**
 * Verify a Standard Webhooks signature. Constant-time compare; rejects
 * out-of-tolerance timestamps and tampered bodies/ids. `secret` is the raw
 * HMAC key (already `decodeWebhookSecret`-ed).
 */
export function verifySignature(opts: {
	webhookId: string;
	webhookTimestamp: string;
	signatureHeader: string;
	body: string;
	secret: Buffer;
	nowUnix: number;
}): VerifyResult {
	const ts = Number.parseInt(opts.webhookTimestamp, 10);
	if (!Number.isFinite(ts))
		return { ok: false, reason: "timestamp not an integer" };
	if (Math.abs(opts.nowUnix - ts) > TOLERANCE_SECONDS) {
		return { ok: false, reason: "timestamp out of tolerance" };
	}

	const signed = `${opts.webhookId}.${opts.webhookTimestamp}.${opts.body}`;
	const expected = crypto
		.createHmac("sha256", opts.secret)
		.update(signed)
		.digest("base64");

	const v1 = parseV1Sigs(opts.signatureHeader);
	if (v1.length === 0) return { ok: false, reason: "no v1 signature entries" };
	const matched = v1.some((s) => timingSafeStrEqual(s, expected));
	return matched ? { ok: true } : { ok: false, reason: "signature mismatch" };
}

/** tenants.plan enum values (planEnum in db/schema.ts). */
export type PlanEnum = "builder" | "team" | "business" | "enterprise";

export type BillingInterval = "month" | "year";

/**
 * Which Polar subscription a lookup key names. `single` = the ordinary monthly
 * plan (one subscription). `base` / `usage` = the two halves of an ANNUAL plan
 * (BILL-02, founder ruling B14 → option (c), 2026-09-16): a yearly BASE product
 * with no meters and a $0 monthly USAGE product carrying the meters and the
 * monthly credits. A yearly product WITH meters grants credits once a YEAR
 * (B-411), which is why the one-object `<plan>_v1_year` keys are gone from
 * this table: an event for one is `unknown` — acked, no plan change.
 */
export type SubscriptionHalf = "single" | "base" | "usage";

/**
 * Polar product `metadata.lookup_key` → (plan enum, interval, half).
 * ADR-076: monthly and annual are SEPARATE Polar products (Polar's own rule —
 * one product per pricing model). Each paid tier carries THREE keys:
 * `<plan>_v1` (monthly, single), `<plan>_v1_base_year` (annual base) and
 * `<plan>_v1_usage_month` (annual usage). All map to the same plan.
 */
const PLAN_KEYS: Record<
	string,
	{ plan: PlanEnum; interval: BillingInterval; half: SubscriptionHalf }
> = {
	builder_v1: { plan: "builder", interval: "month", half: "single" },
	builder_v1_base_year: { plan: "builder", interval: "year", half: "base" },
	builder_v1_usage_month: { plan: "builder", interval: "year", half: "usage" },
	team_v1: { plan: "team", interval: "month", half: "single" },
	team_v1_base_year: { plan: "team", interval: "year", half: "base" },
	team_v1_usage_month: { plan: "team", interval: "year", half: "usage" },
	business_v1: { plan: "business", interval: "month", half: "single" },
	business_v1_base_year: { plan: "business", interval: "year", half: "base" },
	business_v1_usage_month: {
		plan: "business",
		interval: "year",
		half: "usage",
	},
	// Enterprise has no self-serve annual product (custom contract) — monthly
	// key only.
	enterprise_v1: { plan: "enterprise", interval: "month", half: "single" },
};

export type PlanResolution =
	| {
			kind: "plan";
			planEnum: PlanEnum;
			lookupKey: string;
			interval: BillingInterval;
			half: SubscriptionHalf;
	  }
	| { kind: "free"; lookupKey: "free_v1" }
	| { kind: "unknown"; rawKey: string | null };

// `unpaid` is a Polar SUBSCRIPTION STATUS (past the retry schedule, benefits
// revoked on Polar's side) — ADR-076 drops the tenant to Free on it exactly
// like canceled/revoked, with data held (`billing_policy.dunning_data_hold_days`).
const CANCEL_EVENTS = /canceled|revoked/;
const CANCEL_STATUSES = new Set(["canceled", "revoked", "unpaid"]);

/**
 * Resolve the target plan from a subscription event. Canceled/revoked/unpaid
 * → free. A known `lookup_key` → that plan + its interval. Anything else →
 * unknown (caller acks 200 so Polar stops retrying, and logs it; add-on keys
 * are logged loudly).
 */
export function resolvePlan(opts: {
	eventType: string;
	status?: string | null;
	lookupKey?: string | null;
}): PlanResolution {
	const canceled =
		CANCEL_EVENTS.test(opts.eventType) ||
		(opts.status != null && CANCEL_STATUSES.has(opts.status));
	if (canceled) return { kind: "free", lookupKey: "free_v1" };

	const key = opts.lookupKey ?? null;
	const mapped = key ? PLAN_KEYS[key] : undefined;
	if (mapped) {
		return {
			kind: "plan",
			planEnum: mapped.plan,
			lookupKey: key as string,
			interval: mapped.interval,
			half: mapped.half,
		};
	}
	return { kind: "unknown", rawKey: key };
}

/** The (plan, interval, half) a lookup key names, or null for an unknown key —
 *  used by the webhook to place a CANCEL event (which `resolvePlan` resolves to
 *  `free` without a half) on the right half of the pair. */
export function planForLookupKey(key: string | null | undefined): {
	plan: PlanEnum;
	interval: BillingInterval;
	half: SubscriptionHalf;
} | null {
	return key ? (PLAN_KEYS[key] ?? null) : null;
}

// ── BILL-02: the annual PAIR resolver (spec §2.4, P1–P7) ─────────────────

/** The last-seen state of one half of an annual pair (stored verbatim in
 *  `tenants.annual_pair`, written by the webhook only). */
export type PairHalf = {
	id: string;
	plan: string;
	status: string;
	period_start?: string | null;
	period_end?: string | null;
};

export type PairResolution =
	| {
			kind: "annual";
			planEnum: PlanEnum;
			/** the USAGE subscription's cycle — credits and invoices follow it */
			periodStart: string | null;
			periodEnd: string | null;
			/** the base subscription's cycle end — "paid through …" */
			basePeriodEnd: string | null;
			/** P5: the base renewal is in dunning; the tier is kept, the clock runs */
			pastDue?: true;
	  }
	| {
			kind: "refuse";
			reason:
				| "annual_pair_usage_missing"
				| "annual_pair_base_lapsed"
				| "annual_pair_mismatch";
			/** the plan the healthy pair WOULD serve (null on a mismatch) */
			planEnum: PlanEnum | null;
	  }
	| { kind: "none" };

const PLAN_ENUMS: ReadonlySet<string> = new Set([
	"builder",
	"team",
	"business",
	"enterprise",
]);

/** A half counts as "held" while it is paying or in dunning — never after a
 *  cancellation, revocation or `unpaid` (Polar's own end states). */
function halfHeld(h: PairHalf | null | undefined): boolean {
	return !!h && (isActiveStatus(h.status) || isPastDueStatus(h.status));
}

/**
 * Resolve an annual tenant's entitlement from BOTH halves. The ONLY state that
 * serves the tier is P1 (both held, same plan) — and P5, its dunning variant.
 * Every other combination REFUSES: the caller writes `plan = free` with the
 * reason as the alert, the billing page shows it, the reconciler repairs what
 * can be repaired (P2 creates the usage half, P3 cancels it) and reports what
 * cannot (P4). `none` = neither half held → the caller's ordinary
 * drop-to-free path. Pure; the falsification IS the test suite.
 */
export function resolvePair(pair: {
	base?: PairHalf | null;
	usage?: PairHalf | null;
}): PairResolution {
	const base = pair.base ?? null;
	const usage = pair.usage ?? null;
	const baseHeld = halfHeld(base);
	const usageHeld = halfHeld(usage);

	if (!baseHeld && !usageHeld) return { kind: "none" };
	if (baseHeld && !usageHeld) {
		return {
			kind: "refuse",
			reason: "annual_pair_usage_missing",
			planEnum: PLAN_ENUMS.has(base?.plan ?? "")
				? (base?.plan as PlanEnum)
				: null,
		};
	}
	if (!baseHeld && usageHeld) {
		return {
			kind: "refuse",
			reason: "annual_pair_base_lapsed",
			planEnum: PLAN_ENUMS.has(usage?.plan ?? "")
				? (usage?.plan as PlanEnum)
				: null,
		};
	}
	// Both held.
	const b = base as PairHalf;
	const u = usage as PairHalf;
	if (b.plan !== u.plan || !PLAN_ENUMS.has(b.plan)) {
		return { kind: "refuse", reason: "annual_pair_mismatch", planEnum: null };
	}
	const out: PairResolution = {
		kind: "annual",
		planEnum: b.plan as PlanEnum,
		periodStart: u.period_start ?? null,
		periodEnd: u.period_end ?? null,
		basePeriodEnd: b.period_end ?? null,
	};
	if (isPastDueStatus(b.status) || isPastDueStatus(u.status)) {
		return { ...out, pastDue: true };
	}
	return out;
}

/** True on any Polar subscription status meaning "currently paying, healthy". */
export function isActiveStatus(status: string | null | undefined): boolean {
	return status === "active" || status === "trialing";
}

/** True on the "in dunning, still trying to collect" status. */
export function isPastDueStatus(status: string | null | undefined): boolean {
	return status === "past_due";
}

// ── B-388 (2026-09-12): event ordering ──────────────────────────────────────
//
// HMAC + idempotency stop the SAME event applying twice; they say nothing about
// two DIFFERENT events arriving out of order — a retried `subscription.updated`
// (active) delivered after `subscription.canceled` would re-activate the plan.
// The subscription object carries Polar's own clock (`modified_at`); we persist
// the last one applied per tenant and refuse anything older.

/**
 * The event's own clock: Polar's `data.modified_at`, else the Standard Webhooks
 * envelope `timestamp`. `null` when neither parses — the caller then APPLIES
 * (fail-open for the plan state: refusing a customer's paid plan because a
 * timestamp was malformed is the worse failure).
 */
export function eventClock(
	data: Record<string, unknown>,
	envelopeTimestamp: unknown,
): Date | null {
	for (const raw of [data.modified_at, envelopeTimestamp]) {
		if (typeof raw === "string") {
			const d = new Date(raw);
			if (!Number.isNaN(d.getTime())) return d;
		}
	}
	return null;
}

/**
 * True when the stored clock is STRICTLY newer than the event's — the event is
 * a stale retry and must not be applied. Equal clocks apply (Polar can emit
 * `created` and `updated` in the same instant, and the later-received one is
 * idempotently the same state); a missing stored clock (every tenant before
 * this shipped) applies; an unparsable event clock applies.
 */
export function isStale(
	storedAt: Date | null | undefined,
	eventAt: Date | null,
): boolean {
	if (!storedAt || !eventAt) return false;
	return storedAt.getTime() > eventAt.getTime();
}
