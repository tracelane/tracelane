/**
 * The wiring half of lib/csrf.test.ts: the middleware refuses a cross-origin mutation BEFORE
 * AuthKit runs, and leaves same-origin mutations and safe methods to AuthKit unchanged.
 */
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const authkit = vi.fn(async () => new Response(null, { status: 200 }));
vi.mock("@workos-inc/authkit-nextjs", () => ({
	authkitMiddleware: () => authkit,
}));

const { default: middleware } = await import("./middleware");
const event = {} as never;

beforeEach(() => authkit.mockClear());

describe("middleware CSRF gate", () => {
	it("refuses a same-site form POST before AuthKit runs", async () => {
		const res = await middleware(
			new NextRequest("https://app.tracelane.dev/settings/account/email", {
				method: "POST",
				headers: {
					origin: "https://docs.tracelane.dev",
					"sec-fetch-site": "same-site",
					"content-type": "text/plain",
				},
				body: '{"newEmail":"x@evil.example","p":"="}',
			}),
			event,
		);
		expect(res?.status).toBe(403);
		expect(await res?.json()).toEqual({ error: "cross_origin_refused" });
		expect(authkit).not.toHaveBeenCalled();
	});

	it("passes a same-origin mutation to AuthKit", async () => {
		const res = await middleware(
			new NextRequest("https://app.tracelane.dev/api/settings/api-keys", {
				method: "POST",
				headers: { "sec-fetch-site": "same-origin" },
				body: "{}",
			}),
			event,
		);
		expect(res?.status).toBe(200);
		expect(authkit).toHaveBeenCalledTimes(1);
	});

	it("passes a cross-origin GET to AuthKit (navigation is not a mutation)", async () => {
		const res = await middleware(
			new NextRequest("https://app.tracelane.dev/traces", {
				headers: { origin: "https://evil.example" },
			}),
			event,
		);
		expect(res?.status).toBe(200);
		expect(authkit).toHaveBeenCalledTimes(1);
	});
});
