/**
 * The CMK fingerprint must hash the DECODED SPKI DER, never the armored PEM
 * text — the 2026-07-22 audit found the rotate route hashing raw PEM (so the
 * same key re-wrapped produced a "different" fingerprint, and no fingerprint
 * ever reproduced with `openssl ... -outform DER | sha256sum`). Negative case
 * first per .claude/rules/testing.md.
 */

import { describe, expect, it } from "vitest";
import { sha256Fingerprint } from "./cmk-fingerprint";

// Test-only Ed25519 PUBLIC key (no secret material by construction).
const PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApIUZ7ksPPVlPlb7G6PKmnHXoodE+sU03dcNQ9kHIMf8=
-----END PUBLIC KEY-----`;

// Same key, hostile formatting: single-line body, extra blank lines, CRLF.
const PEM_REWRAPPED =
	"-----BEGIN PUBLIC KEY-----\r\n\r\nMCowBQYDK2VwAyEApIUZ7ksPPVlPlb7G6PKmnHXo\r\nodE+sU03dcNQ9kHIMf8=\r\n-----END PUBLIC KEY-----\r\n";

describe("sha256Fingerprint", () => {
	it("never equals a hash of the raw PEM text (the audit bug class)", async () => {
		const fp = await sha256Fingerprint(PEM);
		const pemTextHash = Array.from(
			new Uint8Array(
				await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PEM)),
			),
		)
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");
		expect(fp).not.toBe(pemTextHash);
	});

	it("is identical for the same key regardless of PEM wrapping/whitespace", async () => {
		expect(await sha256Fingerprint(PEM)).toBe(
			await sha256Fingerprint(PEM_REWRAPPED),
		);
	});

	it("emits 64 lowercase hex chars", async () => {
		expect(await sha256Fingerprint(PEM)).toMatch(/^[0-9a-f]{64}$/);
	});
});
