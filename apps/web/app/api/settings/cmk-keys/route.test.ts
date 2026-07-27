/**
 * Tests for `resolveCmkAlgorithm` (backs POST /api/settings/cmk-keys).
 *
 * Regression for V-15: the old `algorithm` heuristic labeled ANY PEM
 * containing "BEGIN PUBLIC KEY" (i.e. every SPKI key, RSA included) as
 * `ed25519`. An RSA-4096 public key — which IS SPKI "BEGIN PUBLIC KEY" — was
 * therefore silently stored as ed25519. These tests parse REAL generated keys
 * and assert the resolved label matches the actual key type, and that anything
 * the platform can't honestly label (wrong RSA size, EC, unparseable) is
 * rejected rather than mislabeled. Negative cases first per
 * `.claude/rules/testing.md`.
 *
 * The function under test is pure (node:crypto + the schema enum only) — no db
 * or auth, so no mocks are needed.
 */

import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { resolveCmkAlgorithm } from "./algorithm";

function publicPem(
	type: "rsa" | "ed25519" | "ec",
	opts: { modulusLength?: number; namedCurve?: string } = {},
): string {
	const { publicKey } = generateKeyPairSync(
		// biome-ignore lint/suspicious/noExplicitAny: keygen option shape varies by algorithm
		type as any,
		{
			...(opts.modulusLength ? { modulusLength: opts.modulusLength } : {}),
			...(opts.namedCurve ? { namedCurve: opts.namedCurve } : {}),
			publicKeyEncoding: { type: "spki", format: "pem" },
			privateKeyEncoding: { type: "pkcs8", format: "pem" },
		},
	);
	return publicKey as string;
}

describe("resolveCmkAlgorithm", () => {
	// ── Negative cases first ──
	it("REJECT: unparseable input → error, never a label", () => {
		const r = resolveCmkAlgorithm("not a pem at all");
		expect(r).toEqual({ error: expect.stringContaining("could not parse") });
	});

	it("REJECT: RSA-2048 (unsupported size) → error, not a false rsa-4096 label", () => {
		const r = resolveCmkAlgorithm(publicPem("rsa", { modulusLength: 2048 }));
		expect("algorithm" in r).toBe(false);
		expect((r as { error: string }).error).toContain("2048");
		expect((r as { error: string }).error).toContain("RSA-4096");
	});

	it("REJECT: EC P-256 (unsupported type) → error", () => {
		const r = resolveCmkAlgorithm(
			publicPem("ec", { namedCurve: "prime256v1" }),
		);
		expect("algorithm" in r).toBe(false);
		expect((r as { error: string }).error).toContain("unsupported key type");
	});

	// ── The regression: RSA-4096 SPKI must NOT be labeled ed25519 ──
	it("ACCEPT: RSA-4096 SPKI public key → rsa-4096 (was mislabeled ed25519)", () => {
		const pem = publicPem("rsa", { modulusLength: 4096 });
		// The exact shape the old heuristic mis-detected:
		expect(pem).toContain("BEGIN PUBLIC KEY");
		expect(resolveCmkAlgorithm(pem)).toEqual({ algorithm: "rsa-4096" });
	});

	it("ACCEPT: Ed25519 public key → ed25519", () => {
		expect(resolveCmkAlgorithm(publicPem("ed25519"))).toEqual({
			algorithm: "ed25519",
		});
	});
});
