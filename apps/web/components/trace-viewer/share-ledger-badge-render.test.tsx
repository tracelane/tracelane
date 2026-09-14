/**
 * `OBS-48` — the three ledger-badge states, asserted against the EXACT copy in
 * `specs/OBS-48-shareable-verified-trace-link.md` §2. A paraphrase that reads
 * fine to a person but drops "operator-signed" or adds "verified" is exactly
 * the honesty-lock defect this test exists to catch (B-249, TRAPS §11) —
 * asserting a substring match on the precise sentence, not merely "renders
 * something", is the point.
 *
 * Also asserts the anchored state NEVER renders an `<a href>` to the Rekor
 * coordinate — the trust-surface guard `AuditLedgerView`'s `LogIndexChip`
 * already enforces (Rekor v2 has no per-entry web page; a plausible URL
 * resolves the wrong, legacy v1 log).
 */

import { ShareLedgerBadge } from "@/components/trace-viewer/ShareLedgerBadge";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

describe("ShareLedgerBadge", () => {
	it("chained=false: not in the audit ledger", () => {
		const html = renderToStaticMarkup(
			h(ShareLedgerBadge, {
				chain: { chained: false, seq: null, anchored: false },
			}),
		);
		expect(html).toContain(
			"Not in the audit ledger (SDK/OTLP traces are not ledgered)",
		);
		// Never any stronger claim leaking in from a shared constant.
		expect(html.toLowerCase()).not.toContain("anchored");
	});

	it("chained && !anchored: operator-signed, with the real seq", () => {
		const html = renderToStaticMarkup(
			h(ShareLedgerBadge, {
				chain: { chained: true, seq: 4812, anchored: false },
			}),
		);
		expect(html).toContain(
			"Recorded in the audit ledger · seq #4,812 · operator-signed",
		);
		expect(html).not.toContain("transparency log");
	});

	it("anchored: transparency-log copy + a non-link Rekor coordinate", () => {
		const html = renderToStaticMarkup(
			h(ShareLedgerBadge, {
				chain: { chained: true, seq: 4812, anchored: true },
				rekorEntryId: "18812240",
			}),
		);
		expect(html).toContain(
			"Recorded in the audit ledger · seq #4,812 · anchored to a public transparency log",
		);
		expect(html).toContain("logIndex 18812240");
		// THE TRUST-SURFACE GUARD: no <a> anywhere carries the Rekor coordinate.
		expect(html).not.toMatch(/<a\s/);
		expect(html).not.toContain("href=");
	});

	it("anchored with no rekor id yet: still no link, still the anchored sentence", () => {
		const html = renderToStaticMarkup(
			h(ShareLedgerBadge, {
				chain: { chained: true, seq: 1, anchored: true },
			}),
		);
		expect(html).toContain("anchored to a public transparency log");
		expect(html).not.toContain("logIndex");
		expect(html).not.toMatch(/<a\s/);
	});

	it("never uses the banned honesty-lock phrases (B-249)", () => {
		for (const chain of [
			{ chained: false, seq: null, anchored: false },
			{ chained: true, seq: 1, anchored: false },
			{ chained: true, seq: 1, anchored: true },
		]) {
			const html = renderToStaticMarkup(
				h(ShareLedgerBadge, { chain, rekorEntryId: "1" }),
			);
			const lower = html.toLowerCase();
			expect(lower).not.toContain("third-party verifiable");
			expect(lower).not.toContain("tamper-proof");
			expect(lower).not.toContain("verified offline");
		}
	});
});
