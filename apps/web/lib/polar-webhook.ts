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

/** Polar product `metadata.lookup_key` → (plan enum, lookup key). */
const PLAN_KEYS: Record<string, PlanEnum> = {
	builder_v1: "builder",
	team_v1: "team",
	business_v1: "business",
	enterprise_v1: "enterprise",
};

/**
 * Add-on / meter lookup keys (ADR-020). These are NOT plans (see ADR-020 / G5)
 * — a subscription event carrying one is a real purchase we do not yet apply
 * (add-on grant wiring is P2), so the caller logs it LOUDLY rather than
 * treating it as a silent unknown.
 */
export const ADD_ON_LOOKUP_KEYS = new Set([
	"audit_addon_v1",
	"overage_v1",
	"team_extra_seat_v1",
	"business_extra_seat_v1",
	"hipaa_gcp_addon_v1",
]);

/** Is `key` a known add-on/meter lookup key (vs a base plan or truly unknown)? */
export function isAddOnLookupKey(key: string | null | undefined): boolean {
	return key != null && ADD_ON_LOOKUP_KEYS.has(key);
}

export type PlanResolution =
	| { kind: "plan"; planEnum: PlanEnum; lookupKey: string }
	| { kind: "free"; lookupKey: "free_v1" }
	| { kind: "unknown"; rawKey: string | null };

const CANCEL_EVENTS = /canceled|revoked/;

/**
 * Resolve the target plan from a subscription event. Canceled/revoked → free.
 * A known `lookup_key` → that plan. Anything else → unknown (caller acks 200
 * so Polar stops retrying, and logs it; add-on keys are logged loudly).
 */
export function resolvePlan(opts: {
	eventType: string;
	status?: string | null;
	lookupKey?: string | null;
}): PlanResolution {
	const canceled =
		CANCEL_EVENTS.test(opts.eventType) ||
		opts.status === "canceled" ||
		opts.status === "revoked";
	if (canceled) return { kind: "free", lookupKey: "free_v1" };

	const key = opts.lookupKey ?? null;
	if (key && key in PLAN_KEYS) {
		return {
			kind: "plan",
			planEnum: PLAN_KEYS[key] as PlanEnum,
			lookupKey: key,
		};
	}
	return { kind: "unknown", rawKey: key };
}
