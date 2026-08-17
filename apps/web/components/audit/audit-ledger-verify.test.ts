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
const render = (
	ndjson: string,
	initialReport?: VerifyReport,
	tenantPubkeyB64?: string,
): string =>
	renderToStaticMarkup(
		h(AuditLedgerView, { ndjson, initialReport, tenantPubkeyB64 }),
	);

let goodNdjson: string;
let tamperedNdjson: string;
let goodReport: VerifyReport;
let tamperedReport: VerifyReport;
// R43/R48 fixtures: a real anchored vector, and the same bytes with the anchor
// demoted to `unanchored` (a batch that is signed but reached no public log).
let anchoredNd: string;
let signedOnlyNd: string;
let anchoredReport: VerifyReport;
let signedOnlyReport: VerifyReport;

beforeAll(async () => {
	goodNdjson = vector("good.ndjson");
	tamperedNdjson = vector("tampered.ndjson");
	// the REAL verifier — same call AuditLedgerView makes on "Verify integrity"
	goodReport = await verifyLedgerText(goodNdjson, { offline: true });
	tamperedReport = await verifyLedgerText(tamperedNdjson, { offline: true });
	anchoredNd = vector("anchored.v1.ndjson");
	signedOnlyNd = anchoredNd
		.split("\n")
		.map((line) =>
			line.includes('"type":"anchor"') || line.includes('"type": "anchor"')
				? line.replace(
						/"anchor_state"\s*:\s*"anchored"/,
						'"anchor_state":"unanchored"',
					)
				: line,
		)
		.join("\n");
	anchoredReport = await verifyLedgerText(anchoredNd, { offline: true });
	signedOnlyReport = await verifyLedgerText(signedOnlyNd, { offline: true });
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

// ---------------------------------------------------------------------------
// R43/R48 — THE STATE→COPY MAPPING, ASSERTED ON THE RENDERED MARKUP.
//
// WHY THESE EXIST, and it is the whole point. The first R43 attempt extracted the
// decision into a pure function and unit-tested THAT. An adversarial pass then
// reinstated BOTH original bugs directly in this component — the operator-signed
// branch made to render "No signed batches yet", and the status line reverted to
// `hasAnchorRecords` — and **all 523 tests still passed.** A pure-function test proves
// the function; it never proves the component calls it correctly. Importing the
// function is the WEAK form of TRAPS §22; the strong form is that a mutation to the
// RENDER PATH turns a test red. These assert the markup, so they do.
// ---------------------------------------------------------------------------

describe("AuditLedgerView — trust states render DISTINCTLY (mutation-catching)", () => {
	it("signed batches + NO fetchable trust root → operator-signed, NEVER 'no batches'", () => {
		// The exact production shape: real anchor records, `tenantPubkeyB64` empty
		// (app/audit/page.tsx does `keyRow?.pubkey ?? ""`). Pre-R43 this rendered
		// "No signed batches yet" over signed data for five live tenants.
		const html = render(signedOnlyNd, signedOnlyReport, "");
		expect(html).toContain("operator-signed");
		expect(html).not.toContain("No signed batches yet");
		expect(html).not.toContain(
			"Signing begins with your first gateway-proxied",
		);
	});

	it("no anchor records at all → the no-batches copy, and ONLY that copy", () => {
		const html = render(goodNdjson, goodReport, "");
		expect(html).toContain("No signed batches yet");
		expect(html).not.toContain("operator-signed");
		expect(html).not.toContain("Tenant-signed");
	});

	it("a record that is NOT anchored must never claim public anchoring", () => {
		// R48: an anchor RECORD exists for every SIGNED batch. Keying the header on
		// record-presence claimed Sigstore inclusion for batches in no log at all.
		const html = render(signedOnlyNd, signedOnlyReport, "");
		expect(html).not.toContain("Publicly anchored");
		expect(html).toContain("Signed, not publicly anchored");
	});

	it("a genuinely anchored record DOES claim public anchoring", () => {
		const html = render(anchoredNd, anchoredReport, "");
		expect(html).toContain("Publicly anchored (Sigstore Rekor v2)");
	});

	it("the three unanchored states share NO headline between them", () => {
		const noBatches = render(goodNdjson, goodReport, "");
		const operator = render(signedOnlyNd, signedOnlyReport, "");
		const tenant = render(signedOnlyNd, signedOnlyReport, "AAAAtestpubkey=");
		expect(noBatches).toContain("No signed batches yet");
		expect(operator).toContain("Tamper-evident, operator-signed");
		expect(tenant).toContain("Tenant-signed (Ed25519)");
		// none may borrow another's headline — the defect was exactly this
		expect(operator).not.toContain("No signed batches yet");
		expect(tenant).not.toContain("Tamper-evident, operator-signed");
		expect(noBatches).not.toContain("Tenant-signed (Ed25519)");
	});
});

describe("AuditLedgerView — a CLAIMED anchor the verifier could not confirm", () => {
	it("says so, borrowing neither the verified nor the not-anchored copy", () => {
		// 1bb14687's exact pre-backfill shape: a real Rekor anchor in the ledger, and
		// no fetchable pubkey, so `anchors_included` stays 0 and nothing is confirmed.
		const html = render(anchoredNd, anchoredReport, "");
		expect(html).toContain("Anchored in the public log — not verified here");
		expect(html).not.toContain("independently verified");
		expect(html).not.toContain("not yet publicly anchored");
		expect(html).not.toContain("No signed batches yet");
	});
});
