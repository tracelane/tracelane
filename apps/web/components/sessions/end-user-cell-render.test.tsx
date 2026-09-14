/**
 * OBS-20 — the `/sessions` User cell, proven against real markup.
 *
 * **The state this test exists for is the third one.** A customer who sends an
 * email address as the end-user id gets `[REDACTED:email]` stored, because
 * ingest runs `pii::redact_json` over every span attribute and `email` is one of
 * its categories. That is the privacy control working exactly as designed — and
 * if it rendered blank, or rendered the raw placeholder, the customer would file
 * a bug against correct behaviour. Three states, three distinguishable renders,
 * asserted rather than assumed:
 *
 *   1. absent / `""` — an em dash. Expected for any tenant that has not
 *      instrumented this, INCLUDING a correctly deployed one.
 *   2. a real id — a LINK to that person's traces. The link is the feature: the
 *      /traces filter has no text input for an opaque id on purpose.
 *   3. `[REDACTED:email]` — the word "redacted", plus a title saying what to
 *      send instead. Never the raw string, never blank.
 *
 * Imports `SessionRow` from this directory rather than from `app/sessions/page.tsx`
 * for the reason that file's header gives. Note `REDACTED_END_USER` comes from
 * `@/lib/end-user`, a module with NO imports — importing it from `@/lib/sessions`
 * drags `@workos-inc/authkit-nextjs` in and breaks collection, which is how this
 * was found.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
	default: ({ href, children, ...rest }: Record<string, unknown>) =>
		createElement("a", { href, ...rest }, children as never),
}));

import { REDACTED_END_USER } from "@/lib/end-user";
import type { SessionSummary } from "@/lib/sessions";
import { SessionRow } from "./SessionRow";

const BASE: SessionSummary = {
	session_id: "sess-obs20-001",
	turns: 3,
	started_at: "2026-09-10 00:00:00.000000",
	last_activity: "2026-09-10 00:05:00.000000",
	duration_us: 300_000_000,
	error_count: 0,
	status: "ok",
	cost_usd: 0.01,
	total_tokens: 100,
	model: "claude-sonnet-4-6",
};

const render = (s: SessionSummary) =>
	renderToStaticMarkup(
		createElement(
			"table",
			null,
			createElement("tbody", null, createElement(SessionRow, { s, win: null })),
		),
	);

describe("OBS-20 end-user cell", () => {
	it("renders an em dash when no end user was sent, for BOTH absent and empty", () => {
		for (const s of [BASE, { ...BASE, end_user: "" }]) {
			const html = render(s);
			expect(html).toContain("—");
			expect(html).not.toContain("redacted");
			// No link — there is nothing to filter to.
			expect(html).not.toContain("end_user=");
		}
	});

	it("renders a real id as a link to that person's traces", () => {
		const html = render({ ...BASE, end_user: "u_4471" });
		expect(html).toContain("u_4471");
		expect(html).toContain("end_user=u_4471");
		// `range=all` matters: an id filtered inside the default 1h window would
		// show an empty list for a user who was active yesterday, which reads as
		// "this person did nothing" rather than "look further back".
		expect(html).toContain("range=all");
		expect(html).not.toContain("redacted");
	});

	// EVERY redaction category, not just email. `crates/policy/src/pii.rs` emits a
	// family, and OBS-20 originally special-cased the email literal alone.
	//
	// THIS TEST USED TO PASS `[REDACTED:email]` AND NOTHING ELSE, which is the one
	// value that passes while the class is broken — an `[REDACTED:ipv4]` was merely
	// "truthy and not the placeholder", so it rendered as a REAL LINK to
	// `/traces?end_user=%5BREDACTED%3Aipv4%5D`, a filter that returns every user
	// redacted the same way. A collision bucket presented as one person's identity.
	// Found by security-reviewer 2026-09-10; the discriminating case is ipv4, not email.
	it.each([
		"[REDACTED:email]",
		"[REDACTED:ipv4]",
		"[REDACTED:phone]",
		"[REDACTED:ssn]",
		"[REDACTED:credit_card]",
	])(
		"renders %s as an explained chip, never raw, never blank, never a link",
		(placeholder) => {
			const html = render({ ...BASE, end_user: placeholder });
			expect(html).toContain("redacted");
			// The raw stored value must not reach the screen.
			expect(html).not.toContain(placeholder);
			// The customer is told what to do instead, in the markup, not in a doc.
			expect(html).toContain("opaque id");
			// NOT a link — filtering to a placeholder every redacted user shares would
			// present a bucket as a person.
			expect(html).not.toContain("end_user=");
		},
	);

	it("REDACTED_END_USER is still one of the family the UI recognises", () => {
		// Guards the constant against drifting away from the pattern that supersedes it.
		const html = render({ ...BASE, end_user: REDACTED_END_USER });
		expect(html).toContain("redacted");
	});

	it("url-encodes an id that would otherwise break the query string", () => {
		const html = render({ ...BASE, end_user: "u/47 &1" });
		expect(html).toContain("end_user=u%2F47%20%261");
	});
});
