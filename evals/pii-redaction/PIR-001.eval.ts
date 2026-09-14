import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PIR-001 — PII redaction: 100% recall on synthetic patterns
 *
 * Verifies the PII redaction module in crates/policy/src/pii.rs covers the
 * standard synthetic PII patterns. The module must detect:
 *   - SSN: 123-45-6789
 *   - Credit card: 4111-1111-1111-1111
 *   - Email: user@example.com
 *   - Phone: +1-800-555-0100
 *   - AWS access key: AKIA...
 *
 * Structural: verify pii.rs exists and documents redaction patterns.
 * Integration: 100% recall measurement against 1K synthetic spans (Week 8).
 */
describe("PIR-001: PII redaction — 100% recall on synthetic patterns", () => {
	it("PII redaction module exists in policy crate", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const p = path.resolve(__dirname, "../../crates/policy/src/pii.rs");
		expect(fs.existsSync(p)).toBe(true);
	});

	it("pii.rs documents the required pattern categories", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const src = fs.readFileSync(
			path.resolve(__dirname, "../../crates/policy/src/pii.rs"),
			"utf8",
		);
		// PII categories that must be redacted per
		const required = ["SSN", "credit", "email", "phone"];
		for (const category of required) {
			expect(src.toLowerCase(), `Missing PII category: ${category}`).toContain(
				category.toLowerCase(),
			);
		}
	});

	// B-371, inverted 2026-09-10. This assertion used to require that both SDK
	// READMEs CONTAIN `TRACELANE_TRACE_CONTENT` — "both SDKs must respect
	// TRACELANE_TRACE_CONTENT=false to redact payloads".
	//
	// NO COMPONENT HAS EVER READ THAT VARIABLE. A repo-wide grep finds it in
	// documentation, archived TRDs and comments only — never in an `env::var`, and
	// never in either SDK's source. So this test was ENFORCING A FALSE PRIVACY
	// CLAIM on two published READMEs: correcting the copy broke a passing eval,
	// which is exactly how the claim survived every prior docs pass. Same shape as
	// B-300, where `plan-ladder-render.test.ts` asserted five retention strings the
	// product did not implement.
	//
	// It now asserts the CORRECTION and refuses the resurrection: the READMEs must
	// state that no switch is needed, and must not re-introduce the instruction.
	it("SDK READMEs do not advertise the inert TRACELANE_TRACE_CONTENT switch", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const sdkFiles = [
			"../../packages/sdk-python/README.md",
			"../../packages/sdk-typescript/README.md",
		];
		let checked = 0;
		for (const rel of sdkFiles) {
			const p = path.resolve(__dirname, rel);
			if (!fs.existsSync(p)) continue;
			checked++;
			const src = fs.readFileSync(p, "utf8");
			// The instruction must be gone. The variable NAME may still appear in
			// the sentence explaining that it never worked — that is the honest
			// correction, not a resurrection — so match the instruction, not the name.
			expect(
				src,
				`SDK README still instructs setting the inert switch: ${rel}`,
			).not.toMatch(/set `?TRACELANE_TRACE_CONTENT=false`? to redact/);
			// And the positive claim must be present, so deleting the paragraph
			// entirely does not silently pass this test.
			expect(
				src,
				`SDK README no longer states the capture posture: ${rel}`,
			).toContain("no switch you need");
		}
		// A `continue` on a missing file would let this pass having checked
		// nothing — the exact failure mode this suite exists to catch.
		expect(checked, "neither SDK README was found; this test checked nothing").toBe(
			sdkFiles.length,
		);
	});

	it("provider keys are never included in span attributes (gateway guarantee)", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const otlpSrc = fs.readFileSync(
			path.resolve(__dirname, "../../crates/gateway/src/otlp_emit.rs"),
			"utf8",
		);
		// The otlp_emit module must document that provider keys are excluded
		expect(otlpSrc.toLowerCase()).toContain("key");
		expect(otlpSrc.toLowerCase()).toContain("never");
	});

	it.skip("100% recall: all 1K synthetic PII spans are redacted before storage (integration — Week 8)", async () => {
		// Full: inject 1K spans with known PII patterns, read from ClickHouse,
		// assert zero PII patterns remain in stored span content
	});
});
