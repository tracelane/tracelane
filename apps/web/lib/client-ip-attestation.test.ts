import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	attestationHeader,
	isValidIp,
	maybeAttestationHeader,
} from "./client-ip-attestation";

const SECRET = "og36-test-attestation-secret-do-not-use-in-prod";
const TOKEN = "test-session-token-not-a-real-jwt";

describe("client IP attestation", () => {
	it("matches an independently computed node:crypto vector", async () => {
		const ip = "203.0.113.5";
		const ts = 1790000000;
		const tokenHash = createHash("sha256").update(TOKEN).digest("hex");
		const mac = createHmac("sha256", SECRET)
			.update(`v1|${ip}|${ts}|${tokenHash}`)
			.digest("hex");
		const expected = `v1;${ip};${ts};${mac}`;
		expect(await attestationHeader(TOKEN, ip, ts, SECRET)).toBe(expected);
		expect(await maybeAttestationHeader(TOKEN, ip, SECRET, ts)).toBe(expected);
	});

	it("returns null for a short secret", async () => {
		expect(
			await maybeAttestationHeader(TOKEN, "203.0.113.5", "too-short", 1),
		).toBeNull();
		expect(
			await maybeAttestationHeader(TOKEN, "203.0.113.5", undefined, 1),
		).toBeNull();
	});

	it("returns null for an invalid IP", async () => {
		for (const bad of ["not-an-ip", "999.1.1.1", "1.2.3", "", null, "a:b:zz"]) {
			expect(await maybeAttestationHeader(TOKEN, bad, SECRET, 1)).toBeNull();
		}
	});

	it("accepts IPv6", () => {
		expect(isValidIp("2001:db8::1")).toBe(true);
		expect(isValidIp("::1")).toBe(true);
	});
});
