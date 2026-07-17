/**
 * Tests for the Polar webhook helpers (signature + plan resolution).
 * Mirrors crates/gateway/src/billing/webhook.rs's verification suite.
 * Negative cases first per .claude/rules/testing.md.
 */

import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	decodeWebhookSecret,
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
	it("maps each known unprefixed plan key", () => {
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
			).toEqual({ kind: "plan", planEnum, lookupKey: key });
		}
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
