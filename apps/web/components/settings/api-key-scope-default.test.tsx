/**
 * The API-key creation dialog must not pre-grant any scope.
 *
 * EARNED 2026-08-20. This dialog defaulted to `["chat", "read", "ingest"]`, so
 * minting a READ-ONLY key meant noticing two boxes were already ticked and
 * un-ticking them. The founder minted a key intending read-only, got one that
 * completed a real Anthropic call, and only discovered it because a proof that
 * required a NON-chat-capable key kept succeeding.
 *
 * Two failures compounded, and either alone would have been survivable:
 *   1. the quiet path — open, name it, Create — granted `chat`, which spends
 *      provider budget;
 *   2. nothing afterwards ever contradicted the operator: the success modal
 *      showed the key and a storage warning, never what the key could DO.
 *
 * So you formed a belief at mint time and the product never tested it. That is
 * the TRAPS §39 shape (right on one axis, blind on another) with the blind axis
 * being the operator's mental model rather than a code check.
 *
 * ASSERTED AGAINST RENDERED MARKUP, not the state array: a test reading the
 * `useState` default would keep passing if the checkboxes were wired to
 * something else (TRAPS §34 — extracting logic moves coverage, it does not
 * create it). What a customer receives is the markup.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { CreateKeyDialog } from "./ApiKeyManager";

function markup(): string {
	return renderToStaticMarkup(
		createElement(CreateKeyDialog, {
			onClose: () => {},
			onCreate: () => {},
			pending: false,
			error: null,
		}),
	);
}

describe("API key creation — scope defaults", () => {
	it("pre-grants NO scope, so the quiet path cannot hand out chat", () => {
		const html = markup();

		// All four scopes are offered. The checkbox carries no `value` attribute —
		// the slug reaches the DOM only through the label — so assert on what is
		// actually rendered rather than on what I assumed was.
		for (const label of ["Chat", "Read", "Ingest", "Admin"]) {
			expect(html, `the ${label} scope must be offered`).toContain(label);
		}
		expect(
			(html.match(/type="checkbox"/g) ?? []).length,
			"all four scopes must render as checkboxes",
		).toBe(4);

		// ...and NONE is checked. React omits the attribute entirely when false,
		// so any occurrence of `checked` in this markup is a pre-granted scope.
		expect(
			html.includes('checked=""') || html.includes("checked="),
			"NO scope checkbox may be pre-checked — a credential dialog whose " +
				"default grants the most is a default that fails OPEN. Minting a " +
				"read-only key must not require noticing and un-ticking boxes.",
		).toBe(false);
	});

	it("refuses to submit with no scope selected, so the empty default is usable", () => {
		const html = markup();
		// The empty default is only acceptable because the form blocks an empty
		// submit and says so. Without this hint the new default would just look
		// broken.
		expect(html).toContain("Pick at least one");
	});
});
