/**
 * Tests for the Polar webhook helpers (signature + plan resolution).
 * Mirrors crates/gateway/src/billing/webhook.rs's verification suite.
 * Negative cases first per .claude/rules/testing.md.
 */

import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	type PairHalf,
	decodeWebhookSecret,
	isActiveStatus,
	isPastDueStatus,
	logSafe,
	resolvePair,
	resolvePlan,
	verifySignature,
} from "./polar-webhook";

// Clearly-marked test key, never a real secret (.claude/rules/testing.md).
const SECRET = Buffer.from("unit-test-polar-secret-do-not-use");

function v1Header(
	webhookId: string,
	ts: number,
	body: string,
	secret: Buffer,
): string {
	const signed = `${webhookId}.${ts}.${body}`;
	return `v1,${crypto.createHmac("sha256", secret).update(signed).digest("base64")}`;
}

describe("verifySignature", () => {
	const id = "msg_01HABCDE";
	const body = '{"id":"evt_1","type":"subscription.created"}';
	const now = 1_700_000_000;

	it("REJECT: wrong secret", () => {
		const header = v1Header(id, now, body, Buffer.from("wrong-secret"));
		const r = verifySignature({
			webhookId: id,
			webhookTimestamp: String(now),
			signatureHeader: header,
			body,
			secret: SECRET,
			nowUnix: now,
		});
		expect(r.ok).toBe(false);
	});

	it("REJECT: replayed (timestamp out of tolerance)", () => {
		const header = v1Header(id, now, body, SECRET);
		const r = verifySignature({
			webhookId: id,
			webhookTimestamp: String(now),
			signatureHeader: header,
			body,
			secret: SECRET,
			nowUnix: now + 600,
		});
		expect(r.ok).toBe(false);
	});

	it("REJECT: tampered body", () => {
		const header = v1Header(id, now, body, SECRET);
		const r = verifySignature({
			webhookId: id,
			webhookTimestamp: String(now),
			signatureHeader: header,
			body: '{"id":"evt_1","type":"subscription.canceled"}',
			secret: SECRET,
			nowUnix: now,
		});
		expect(r.ok).toBe(false);
	});

	it("REJECT: tampered webhook id", () => {
		const header = v1Header(id, now, body, SECRET);
		const r = verifySignature({
			webhookId: "msg_attacker",
			webhookTimestamp: String(now),
			signatureHeader: header,
			body,
			secret: SECRET,
			nowUnix: now,
		});
		expect(r.ok).toBe(false);
	});

	it("REJECT: no v1 entries", () => {
		const r = verifySignature({
			webhookId: id,
			webhookTimestamp: String(now),
			signatureHeader: "v0,abc",
			body,
			secret: SECRET,
			nowUnix: now,
		});
		expect(r.ok).toBe(false);
	});

	it("ACCEPT: valid signature", () => {
		const header = v1Header(id, now, body, SECRET);
		const r = verifySignature({
			webhookId: id,
			webhookTimestamp: String(now),
			signatureHeader: header,
			body,
			secret: SECRET,
			nowUnix: now,
		});
		expect(r.ok).toBe(true);
	});

	it("ACCEPT: one of multiple v1 entries matches (rotation window)", () => {
		const real = v1Header(id, now, body, SECRET);
		const header = `${real} v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`;
		const r = verifySignature({
			webhookId: id,
			webhookTimestamp: String(now),
			signatureHeader: header,
			body,
			secret: SECRET,
			nowUnix: now,
		});
		expect(r.ok).toBe(true);
	});
});

describe("decodeWebhookSecret (Polar keying)", () => {
	// Clearly-marked fake secret; shaped like Polar's `polar_whs_…` but bogus.
	const RAW = "polar_whs_unit_test_do_not_use_in_prod";

	it("uses the raw UTF-8 secret string as the key (no base64 decode, prefix kept)", () => {
		expect(decodeWebhookSecret(RAW).equals(Buffer.from(RAW, "utf-8"))).toBe(
			true,
		);
	});

	it("matches the key @polar-sh/sdk derives (base64(utf8) → SW base64-decode round-trips)", () => {
		// Replicate Polar's validateEvent: base64-encode the secret, then the
		// standardwebhooks Webhook ctor base64-decodes it (no `whsec_` prefix).
		const base64Secret = Buffer.from(RAW, "utf-8").toString("base64");
		const sdkKey = Buffer.from(base64Secret, "base64");
		expect(decodeWebhookSecret(RAW).equals(sdkKey)).toBe(true);
	});

	it("trims a stray trailing newline from the env var", () => {
		expect(decodeWebhookSecret(`${RAW}\n`).equals(Buffer.from(RAW))).toBe(true);
	});

	it("ACCEPT: a signature produced with Polar's keying verifies end-to-end", () => {
		const id = "msg_polar";
		const body = '{"id":"evt_2","type":"subscription.created"}';
		const now = 1_700_000_000;
		// Polar signs with key = utf8(secret); decodeWebhookSecret must agree.
		const header = v1Header(id, now, body, decodeWebhookSecret(RAW));
		const r = verifySignature({
			webhookId: id,
			webhookTimestamp: String(now),
			signatureHeader: header,
			body,
			secret: decodeWebhookSecret(RAW),
			nowUnix: now,
		});
		expect(r.ok).toBe(true);
	});
});

describe("resolvePlan", () => {
	it("maps each known unprefixed MONTHLY plan key, interval='month'", () => {
		for (const [key, planEnum] of [
			["builder_v1", "builder"],
			["team_v1", "team"],
			["business_v1", "business"],
			["enterprise_v1", "enterprise"],
		] as const) {
			expect(
				resolvePlan({
					eventType: "subscription.created",
					lookupKey: key,
				}),
			).toEqual({
				kind: "plan",
				planEnum,
				lookupKey: key,
				interval: "month",
				half: "single",
			});
		}
	});

	it("BILL-02: the _base_year and _usage_month keys map to the SAME plan, interval='year', each naming its HALF", () => {
		for (const [plan, planEnum] of [
			["builder_v1", "builder"],
			["team_v1", "team"],
			["business_v1", "business"],
		] as const) {
			expect(
				resolvePlan({
					eventType: "subscription.created",
					lookupKey: `${plan}_base_year`,
				}),
			).toEqual({
				kind: "plan",
				planEnum,
				lookupKey: `${plan}_base_year`,
				interval: "year",
				half: "base",
			});
			expect(
				resolvePlan({
					eventType: "subscription.created",
					lookupKey: `${plan}_usage_month`,
				}),
			).toEqual({
				kind: "plan",
				planEnum,
				lookupKey: `${plan}_usage_month`,
				interval: "year",
				half: "usage",
			});
		}
	});

	it("the retired one-object `_year` key (credits once a YEAR, B-411) is UNKNOWN — acked, no plan change", () => {
		expect(
			resolvePlan({
				eventType: "subscription.created",
				lookupKey: "builder_v1_year",
			}),
		).toEqual({ kind: "unknown", rawKey: "builder_v1_year" });
	});

	it("Enterprise has NO annual product — enterprise_v1_year is unknown", () => {
		expect(
			resolvePlan({
				eventType: "subscription.created",
				lookupKey: "enterprise_v1_year",
			}),
		).toEqual({ kind: "unknown", rawKey: "enterprise_v1_year" });
	});

	it("canceled/revoked event → free", () => {
		expect(
			resolvePlan({
				eventType: "subscription.canceled",
				lookupKey: "team_v1",
			}),
		).toEqual({ kind: "free", lookupKey: "free_v1" });
	});

	it("canceled status → free even on an update event", () => {
		expect(
			resolvePlan({
				eventType: "subscription.updated",
				status: "canceled",
				lookupKey: "team_v1",
			}),
		).toEqual({ kind: "free", lookupKey: "free_v1" });
	});

	it("ADR-076: unpaid status (dunning exhausted) → free, same as canceled/revoked", () => {
		expect(
			resolvePlan({
				eventType: "subscription.updated",
				status: "unpaid",
				lookupKey: "team_v1",
			}),
		).toEqual({ kind: "free", lookupKey: "free_v1" });
	});

	it("unknown / missing key → unknown", () => {
		expect(
			resolvePlan({
				eventType: "subscription.created",
				lookupKey: "bogus_v1",
			}),
		).toEqual({ kind: "unknown", rawKey: "bogus_v1" });
		expect(
			resolvePlan({
				eventType: "subscription.created",
				lookupKey: null,
			}),
		).toEqual({ kind: "unknown", rawKey: null });
	});
});

describe("resolvePair — BILL-02 §2.4, every half-state REFUSES (falsification is the test)", () => {
	const base = (over: Partial<PairHalf> = {}): PairHalf => ({
		id: "sub_base",
		plan: "team",
		status: "active",
		period_start: null,
		period_end: "2027-09-14T00:00:00Z",
		...over,
	});
	const usage = (over: Partial<PairHalf> = {}): PairHalf => ({
		id: "sub_usage",
		plan: "team",
		status: "active",
		period_start: "2026-09-14T00:00:00Z",
		period_end: "2026-10-14T00:00:00Z",
		...over,
	});

	it("P1: base ACTIVE + usage ACTIVE on the same plan → the tier, interval year, the USAGE cycle as the period", () => {
		expect(resolvePair({ base: base(), usage: usage() })).toEqual({
			kind: "annual",
			planEnum: "team",
			periodStart: "2026-09-14T00:00:00Z",
			periodEnd: "2026-10-14T00:00:00Z",
			basePeriodEnd: "2027-09-14T00:00:00Z",
		});
	});

	it("P2: base ACTIVE + usage MISSING (never created) → REFUSED to free, alert usage_missing", () => {
		expect(resolvePair({ base: base(), usage: null })).toEqual({
			kind: "refuse",
			reason: "annual_pair_usage_missing",
			planEnum: "team",
		});
	});

	it("P2: base ACTIVE + usage CANCELED → REFUSED, alert usage_missing", () => {
		expect(
			resolvePair({ base: base(), usage: usage({ status: "canceled" }) }),
		).toMatchObject({ kind: "refuse", reason: "annual_pair_usage_missing" });
	});

	it("P3: base LAPSED (canceled / revoked / unpaid) + usage ACTIVE → REFUSED, alert base_lapsed", () => {
		for (const status of ["canceled", "revoked", "unpaid"]) {
			expect(
				resolvePair({ base: base({ status }), usage: usage() }),
			).toMatchObject({ kind: "refuse", reason: "annual_pair_base_lapsed" });
		}
	});

	it("P4: base plan ≠ usage plan → REFUSED, alert mismatch, NO repair hint", () => {
		expect(
			resolvePair({
				base: base({ plan: "team" }),
				usage: usage({ plan: "builder" }),
			}),
		).toEqual({
			kind: "refuse",
			reason: "annual_pair_mismatch",
			planEnum: null,
		});
	});

	it("P5: base PAST_DUE (renewal failed) + usage ACTIVE → the tier is KEPT and dunning is flagged, never a refusal (ingest is never gated on billing state)", () => {
		expect(
			resolvePair({ base: base({ status: "past_due" }), usage: usage() }),
		).toEqual({
			kind: "annual",
			planEnum: "team",
			periodStart: "2026-09-14T00:00:00Z",
			periodEnd: "2026-10-14T00:00:00Z",
			basePeriodEnd: "2027-09-14T00:00:00Z",
			pastDue: true,
		});
	});

	it("neither half active → `none` (the caller's ordinary drop-to-free path)", () => {
		expect(
			resolvePair({
				base: base({ status: "canceled" }),
				usage: usage({ status: "canceled" }),
			}),
		).toEqual({ kind: "none" });
		expect(resolvePair({ base: null, usage: null })).toEqual({ kind: "none" });
	});

	it("usage ACTIVE + base MISSING (never existed) → REFUSED base_lapsed: a $0 usage subscription alone is the tier for free", () => {
		expect(resolvePair({ base: null, usage: usage() })).toMatchObject({
			kind: "refuse",
			reason: "annual_pair_base_lapsed",
		});
	});
});

describe("isActiveStatus / isPastDueStatus", () => {
	it("active and trialing both read as active", () => {
		expect(isActiveStatus("active")).toBe(true);
		expect(isActiveStatus("trialing")).toBe(true);
		expect(isActiveStatus("past_due")).toBe(false);
		expect(isActiveStatus(null)).toBe(false);
		expect(isActiveStatus(undefined)).toBe(false);
	});

	it("only past_due reads as past-due", () => {
		expect(isPastDueStatus("past_due")).toBe(true);
		expect(isPastDueStatus("active")).toBe(false);
		expect(isPastDueStatus("unpaid")).toBe(false);
	});
});

describe("logSafe — log-injection guard", () => {
	// Negative cases first (.claude/rules/testing.md): the forged-entry shapes
	// this exists to stop. A raw CR/LF in a Polar-relayed, customer-controlled
	// field would otherwise write a second, entirely fabricated log line.
	it("collapses CR/LF so a customer-controlled field cannot forge a log entry", () => {
		const forged = "audit_v1\n[polar-webhook] plan upgraded to enterprise";
		const safe = logSafe(forged);
		expect(safe).not.toContain("\n");
		expect(safe.split("\n")).toHaveLength(1);
		// The text survives (still diagnosable) — only the line break is neutralised.
		expect(safe).toContain("audit_v1");
		expect(safe).toContain("plan upgraded to enterprise");
	});

	it("strips CR and the other C0 controls, not just LF", () => {
		expect(logSafe("a\rb")).toBe("a\ufffdb");
		expect(logSafe("a\u0000b")).toBe("a\ufffdb");
		expect(logSafe("a\u001bb")).toBe("a\ufffdb"); // ESC — terminal escape sequences
		expect(logSafe("a\u007fb")).toBe("a\ufffdb"); // DEL
	});

	it("caps length so one field cannot push the real entry out of view", () => {
		expect(logSafe("x".repeat(5000))).toHaveLength(200);
	});

	it("renders non-strings as their type instead of coercing", () => {
		expect(logSafe(null)).toBe("null");
		expect(logSafe(undefined)).toBe("undefined");
		expect(logSafe({ evil: "\ntoString" })).toBe("object");
	});

	it("leaves an ordinary value untouched", () => {
		expect(logSafe("audit_addon_v1")).toBe("audit_addon_v1");
	});
});

// ── B-388: event ordering ────────────────────────────────────────────────────
import { eventClock, isStale } from "./polar-webhook";

describe("B-388 eventClock", () => {
	it("prefers Polar's data.modified_at over the envelope timestamp", () => {
		const d = eventClock(
			{ modified_at: "2026-09-12T10:00:00Z" },
			"2026-09-12T11:00:00Z",
		);
		expect(d?.toISOString()).toBe("2026-09-12T10:00:00.000Z");
	});
	it("falls back to the envelope timestamp", () => {
		const d = eventClock({}, "2026-09-12T11:00:00Z");
		expect(d?.toISOString()).toBe("2026-09-12T11:00:00.000Z");
	});
	it("returns null when neither parses (the caller then APPLIES)", () => {
		expect(eventClock({ modified_at: "not a date" }, 12345)).toBeNull();
		expect(eventClock({}, undefined)).toBeNull();
	});
});

describe("B-388 isStale", () => {
	const t1 = new Date("2026-09-12T10:00:00Z");
	const t2 = new Date("2026-09-12T10:00:01Z");
	it("STALE: the stored clock is newer than the event's", () => {
		expect(isStale(t2, t1)).toBe(true);
	});
	it("not stale: equal clocks apply (created + updated in one instant)", () => {
		expect(isStale(t1, new Date(t1))).toBe(false);
	});
	it("not stale: a newer event applies", () => {
		expect(isStale(t1, t2)).toBe(false);
	});
	it("not stale: no stored clock (every tenant before this shipped)", () => {
		expect(isStale(null, t1)).toBe(false);
		expect(isStale(undefined, t1)).toBe(false);
	});
	it("not stale: an unparsable event clock applies (fail-open for the plan)", () => {
		expect(isStale(t2, null)).toBe(false);
	});
});
