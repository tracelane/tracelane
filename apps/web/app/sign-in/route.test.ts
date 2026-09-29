/** /sign-in forwards a SAFE returnTo to AuthKit, and drops an unsafe one. */
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	getSignInUrl: vi.fn(async () => "https://auth.example/authorize"),
	redirect: vi.fn((url: string) => {
		throw new Error(`NEXT_REDIRECT:${url}`);
	}),
}));
vi.mock("@workos-inc/authkit-nextjs", () => ({ getSignInUrl: h.getSignInUrl }));
vi.mock("next/navigation", () => ({ redirect: h.redirect }));

import type { NextRequest } from "next/server";
import { GET } from "./route";

const req = (qs: string) =>
	({
		nextUrl: new URL(`https://app.example/sign-in${qs}`),
	}) as unknown as NextRequest;

beforeEach(() => h.getSignInUrl.mockClear());

describe("/sign-in", () => {
	it("resumes a same-origin page after signing in", async () => {
		await expect(GET(req("?returnTo=%2Ftraces%3Fmodel%3Dx"))).rejects.toThrow(
			"NEXT_REDIRECT",
		);
		expect(h.getSignInUrl).toHaveBeenCalledWith({
			returnTo: "/traces?model=x",
		});
	});

	it("drops an open-redirect attempt", async () => {
		await expect(GET(req("?returnTo=%2F%2Fevil.example"))).rejects.toThrow(
			"NEXT_REDIRECT",
		);
		expect(h.getSignInUrl).toHaveBeenCalledWith(undefined);
	});

	it("plain /sign-in behaves as before", async () => {
		await expect(GET(req(""))).rejects.toThrow("NEXT_REDIRECT");
		expect(h.getSignInUrl).toHaveBeenCalledWith(undefined);
	});
});
