// @vitest-environment jsdom
/**
 * 2026-09-27 — an expired session's API call arrives as a REDIRECT (route 307 →
 * /sign-in → WorkOS, cross-origin). Followed, that is a CORS TypeError nothing can read;
 * `redirect: "manual"` turns it into an `opaqueredirect`, which must send the browser to
 * sign-in rather than resolve or throw.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { apiFetch, apiFetchRaw } from "./api-fetch";

const hrefSet = vi.fn();
function stubLocation() {
	Object.defineProperty(window, "location", {
		configurable: true,
		value: {
			pathname: "/settings/gateway",
			search: "?tab=aliases",
			set href(v: string) {
				hrefSet(v);
			},
		},
	});
}

afterEach(() => {
	vi.unstubAllGlobals();
	hrefSet.mockReset();
});

const settles = (p: Promise<unknown>) =>
	Promise.race([
		p.then(
			() => "settled",
			() => "settled",
		),
		new Promise((r) => setTimeout(() => r("pending"), 50)),
	]);

describe("apiFetchRaw", () => {
	it("asks fetch NOT to follow redirects", async () => {
		const f = vi.fn(async () => Response.json({ ok: 1 }));
		vi.stubGlobal("fetch", f);
		await apiFetchRaw("/api/x", { method: "PUT" });
		expect(f).toHaveBeenCalledWith("/api/x", {
			method: "PUT",
			redirect: "manual",
		});
	});

	it("an opaque redirect (expired session) goes to /sign-in and never settles", async () => {
		stubLocation();
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					({
						type: "opaqueredirect",
						status: 0,
						ok: false,
						headers: new Headers(),
					}) as unknown as Response,
			),
		);
		expect(await settles(apiFetch("/api/x"))).toBe("pending");
		expect(hrefSet).toHaveBeenCalledWith(
			"/sign-in?returnTo=%2Fsettings%2Fgateway%3Ftab%3Daliases",
		);
	});

	it("a same-origin 307 is treated the same way", async () => {
		stubLocation();
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(null, {
						status: 307,
						headers: { location: "/sign-in" },
					}),
			),
		);
		expect(await settles(apiFetchRaw("/api/x"))).toBe("pending");
		expect(hrefSet).toHaveBeenCalledWith(
			"/sign-in?returnTo=%2Fsettings%2Fgateway%3Ftab%3Daliases",
		);
	});

	it("an ordinary JSON answer is returned untouched", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => Response.json({ items: [] })),
		);
		expect(await apiFetch<{ items: unknown[] }>("/api/x")).toEqual({
			items: [],
		});
	});
});
