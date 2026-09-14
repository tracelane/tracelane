/**
 * `OBS-48` — the share dialog's listing + revoke logic and the two link-row
 * shapes.
 *
 * This repo's vitest config runs component tests in the `node` environment
 * (no jsdom, no user-event — see `vitest.config.ts`'s own comment on why), so
 * "click Revoke and watch the list update" cannot be simulated as a DOM
 * interaction here. Instead: the STATE TRANSITIONS `ShareDialog` calls on
 * revoke/mint (`removeLink`, `withMinted`) are exported as pure functions and
 * tested directly, and the two visual shapes a list row can take
 * (`ShareLinkRow`) are asserted via `renderToStaticMarkup` — together these
 * cover "does revoking take the link out of the list" and "does the list
 * render both shapes correctly" without needing a live DOM.
 */

import {
	type ShareLink,
	ShareLinkRow,
	removeLink,
	shareErrorMessage,
	withMinted,
} from "@/components/trace-viewer/ShareDialog";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

const LINK_A: ShareLink = {
	id: "a",
	created_at: "2026-09-01T00:00:00Z",
	expires_at: "2026-10-01T00:00:00Z",
	view_count: 12,
};
const LINK_B: ShareLink = {
	id: "b",
	created_at: "2026-09-02T00:00:00Z",
	expires_at: "2026-10-02T00:00:00Z",
	view_count: 0,
};

describe("removeLink (revoke logic)", () => {
	it("removes only the matching id, leaving the rest untouched", () => {
		expect(removeLink([LINK_A, LINK_B], "a")).toEqual([LINK_B]);
	});

	it("is a no-op when the id is not present", () => {
		const links = [LINK_A, LINK_B];
		expect(removeLink(links, "does-not-exist")).toEqual(links);
	});

	it("handles an empty list", () => {
		expect(removeLink([], "a")).toEqual([]);
	});
});

describe("withMinted (mint logic)", () => {
	it("prepends the new link with view_count 0", () => {
		const next = withMinted([LINK_A], {
			id: "c",
			token: "unused-here",
			url: "https://app.tracelane.dev/s/tok",
			expires_at: "2026-12-01T00:00:00Z",
		});
		expect(next).toHaveLength(2);
		expect(next[0]?.id).toBe("c");
		expect(next[0]?.view_count).toBe(0);
		expect(next[1]).toEqual(LINK_A);
	});
});

describe("shareErrorMessage", () => {
	it("403 always becomes the fixed permission sentence — never the raw body", () => {
		expect(shareErrorMessage(403, { error: "some upstream text" })).toBe(
			"Your role doesn't have permission to share this trace.",
		);
	});

	it("carries the gateway's own message through for other statuses (e.g. 409 over-cap)", () => {
		expect(
			shareErrorMessage(409, {
				error: "You have reached the maximum of 10 active links.",
			}),
		).toBe("You have reached the maximum of 10 active links.");
	});

	it("falls back to a generic-but-honest sentence when the body carries nothing usable", () => {
		expect(shareErrorMessage(500, null)).toBe(
			"Couldn't complete that action. Nothing was recorded.",
		);
		expect(shareErrorMessage(500, {})).toBe(
			"Couldn't complete that action. Nothing was recorded.",
		);
	});
});

describe("ShareLinkRow", () => {
	it("an older link (no mintedUrl) shows created/expiry/views and Revoke, never a bare URL", () => {
		const html = renderToStaticMarkup(
			h(ShareLinkRow, {
				link: LINK_A,
				revoking: false,
				onRevoke: vi.fn(),
			}),
		);
		expect(html).toContain("12 views");
		expect(html).toContain("Revoke");
		expect(html).not.toContain("/s/");
	});

	it("a just-minted link shows the full copyable URL", () => {
		const html = renderToStaticMarkup(
			h(ShareLinkRow, {
				link: LINK_B,
				mintedUrl: "https://app.tracelane.dev/s/abc123",
				revoking: false,
				onRevoke: vi.fn(),
			}),
		);
		expect(html).toContain("https://app.tracelane.dev/s/abc123");
		expect(html).toContain("0 views");
	});

	it("shows the busy label while revoking", () => {
		const html = renderToStaticMarkup(
			h(ShareLinkRow, { link: LINK_A, revoking: true, onRevoke: vi.fn() }),
		);
		expect(html).toContain("Revoking…");
	});
});
