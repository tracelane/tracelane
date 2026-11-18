// @vitest-environment jsdom
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
	SHARE_LINK_SCOPE,
	ShareDialog,
	type ShareLink,
	ShareLinkRow,
	buildReviewNote,
	removeLink,
	shareErrorMessage,
	withMinted,
} from "@/components/trace-viewer/ShareDialog";
import { apiFetchRaw } from "@/lib/api-fetch";
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

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

describe("buildReviewNote", () => {
	it("contains the exact public-link scope and UTC expiry", () => {
		expect(
			buildReviewNote(
				"https://app.tracelane.dev/s/testtoken",
				"2026-12-01 00:00:00",
			),
		).toBe(
			[
				"Tracelane trace review (read-only)",
				"Link: https://app.tracelane.dev/s/testtoken",
				"Expires: Dec 1, 2026 · 00:00 UTC",
				"Anyone with this link can open it without signing in. Forward it only to people who should see it.",
				SHARE_LINK_SCOPE,
				"Prompts, responses and tool bodies are not included.",
				"This is one trace, not proof of a complete audit ledger.",
			].join("\n"),
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
		expect(html).toContain("Copy review note");
	});

	it("shows the busy label while revoking", () => {
		const html = renderToStaticMarkup(
			h(ShareLinkRow, { link: LINK_A, revoking: true, onRevoke: vi.fn() }),
		);
		expect(html).toContain("Revoking…");
	});
});

vi.mock("@/lib/api-fetch", () => ({ apiFetchRaw: vi.fn() }));
afterEach(() => {
	cleanup();
	vi.resetAllMocks();
});

describe("revoke outcomes", () => {
	it.each([
		{ status: 204, removed: true },
		{ status: 404, removed: false },
		{ status: 500, removed: false },
	])("DELETE $status: removed=$removed", async ({ status, removed }) => {
		vi.mocked(apiFetchRaw)
			.mockResolvedValueOnce(new Response(JSON.stringify([LINK_A, LINK_B])))
			.mockResolvedValueOnce(new Response(null, { status }));
		render(h(ShareDialog, { traceId: "trace", embedded: true }));
		const revoke = await screen.findAllByRole("button", { name: "Revoke" });
		const first = revoke[0];
		if (!first) throw new Error("Expected a revoke button");
		fireEvent.click(first);
		if (removed) {
			await waitFor(() => expect(screen.queryByText(/12 views/)).toBeNull());
			expect(screen.getByText(/0 views/)).toBeTruthy();
		} else {
			expect(await screen.findByRole("alert")).toBeTruthy();
			expect(screen.getByText(/12 views/)).toBeTruthy();
		}
		expect(vi.mocked(apiFetchRaw).mock.calls).toHaveLength(2);
	});

	it("a 404 keeps the row and says the link was not revoked", async () => {
		vi.mocked(apiFetchRaw)
			.mockResolvedValueOnce(new Response(JSON.stringify([LINK_A, LINK_B])))
			.mockResolvedValueOnce(new Response(null, { status: 404 }));
		render(h(ShareDialog, { traceId: "trace", embedded: true }));
		const revoke = await screen.findAllByRole("button", { name: "Revoke" });
		const first = revoke[0];
		if (!first) throw new Error("Expected a revoke button");
		fireEvent.click(first);
		const alert = await screen.findByRole("alert");
		expect(alert.textContent).toContain("was not revoked");
		expect(screen.getByText(/12 views/)).toBeTruthy();
		expect(screen.getByText(/0 views/)).toBeTruthy();
	});
});

describe("share link scope", () => {
	it.each([
		"workspace name",
		"trace, span and agent IDs",
		"guardrail verdicts",
		"numeric and boolean attributes",
		"ledger position and anchor status",
	])("names %s", (field) => {
		expect(SHARE_LINK_SCOPE).toContain(field);
	});

	it("an empty list never implies no live links exist anywhere", async () => {
		vi.mocked(apiFetchRaw).mockResolvedValueOnce(
			new Response(JSON.stringify([])),
		);
		render(h(ShareDialog, { traceId: "trace", embedded: true }));
		expect(
			await screen.findByText("No active links in your current workspace"),
		).toBeTruthy();
	});
});

it("renders the public-link warning and the Reviewer note label", () => {
	const html = renderToStaticMarkup(
		h(ShareDialog, { traceId: "trace", embedded: true }),
	);
	expect(html).toContain(
		"Anyone with this link can open it without signing in, until it expires or is revoked.",
	);
	const row = renderToStaticMarkup(
		h(ShareLinkRow, {
			link: LINK_A,
			mintedUrl: "https://app.tracelane.dev/s/token",
			revoking: false,
			onRevoke: vi.fn(),
		}),
	);
	expect(row).toContain("Reviewer note");
	expect(row).not.toContain("URL and expiry only");
});
