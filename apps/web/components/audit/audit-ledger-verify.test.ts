import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type VerifyReport,
	verifyLedgerText,
} from "@tracelanedev/audit-verifier";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeAll, describe, expect, it } from "vitest";
import { AuditLedgerView } from "./AuditLedgerView";

/**
 * Proof that the Audit page verdict is REAL, not a static "Verified ✓" string —
 * the whole point of the one place we make the tamper-evident claim.
 *
 * Chains real bytes → real verifier → real component:
 *   1. Load the canonical conformance vectors (evals/audit-ledger/{good,tampered}.ndjson).
 *   2. Run the SAME open-source verifier the component calls (verifyLedgerText,
 *      offline) — it recomputes every row hash + the prev-hash chain.
 *   3. Render AuditLedgerView with that real report and assert the verdict UI:
 *      a VALID chain → green "Verified", a TAMPERED chain → red "Chain broken",
 *      and NO report → no verdict at all. The component cannot show green for an
 *      invalid (or absent) report.
 *
 * Node env (no jsdom): we seed the already-verified state via the `initialReport`
 * seam and assert the static markup — the verdict branch is purely a function of
 * `report.hash_chain_valid`.
 */

const here = dirname(fileURLToPath(import.meta.url));
const vector = (name: string): string =>
	readFileSync(resolve(here, "../../../../evals/audit-ledger", name), "utf8");

const h = createElement;
const render = (ndjson: string, initialReport?: VerifyReport): string =>
	renderToStaticMarkup(h(AuditLedgerView, { ndjson, initialReport }));

let goodNdjson: string;
let tamperedNdjson: string;
let goodReport: VerifyReport;
let tamperedReport: VerifyReport;

beforeAll(async () => {
	goodNdjson = vector("good.ndjson");
	tamperedNdjson = vector("tampered.ndjson");
	// the REAL verifier — same call AuditLedgerView makes on "Verify integrity"
	goodReport = await verifyLedgerText(goodNdjson, { offline: true });
	tamperedReport = await verifyLedgerText(tamperedNdjson, { offline: true });
});

describe("audit verifier — real recompute over canonical vectors (not a server boolean)", () => {
	it("the good vector verifies (100 rows, chain valid)", () => {
		expect(goodReport.hash_chain_valid).toBe(true);
		expect(goodReport.rows_seen).toBe(100);
	});

	it("the tampered vector FAILS the chain check with row errors", () => {
		expect(tamperedReport.hash_chain_valid).toBe(false);
		expect(tamperedReport.errors.length).toBeGreaterThan(0);
	});

	it("resolves no Rekor anchor for an unanchored vector (no green claim basis)", () => {
		expect(goodReport.rekor_anchors_resolved).toBe(0);
		expect(goodReport.anchors_included).toBe(0);
	});
});

describe("AuditLedgerView — verdict UI is a function of the real report", () => {
	it("a VALID report renders the green chain verdict", () => {
		const html = render(goodNdjson, goodReport);
		expect(html).toContain("Verified ·");
		expect(html).toContain("100 rows");
		expect(html).toContain("off-platform reproducible");
		expect(html).not.toContain("Chain broken");
	});

	it("a TAMPERED report renders RED 'Chain broken', never green", () => {
		const html = render(tamperedNdjson, tamperedReport);
		expect(html).toContain("Chain broken");
		expect(html).toContain("recomputed hashes do not match");
		expect(html).toContain("at seq");
		// the failing chain must NOT borrow the green verdict's wording
		expect(html).not.toContain("off-platform reproducible");
	});

	it("with NO report, renders NO verdict — only the Verify button (no static claim)", () => {
		const html = render(goodNdjson, undefined);
		expect(html).toContain("Verify integrity");
		expect(html).not.toContain("Verified ·");
		expect(html).not.toContain("Chain broken");
	});

	it("never shows a green public-anchor claim without a verified inclusion proof", () => {
		const html = render(goodNdjson, goodReport);
		// good.ndjson has no anchor records → honest neutral state, never green.
		expect(html).toContain("No signed batches yet");
		expect(html).not.toContain("Publicly anchored");
		expect(html).not.toContain("independently verified");
		expect(html).not.toContain("Signature verified");
	});
});
