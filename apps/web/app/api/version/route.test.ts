/**
 * GET /api/version answers the BAKED build sha — the deploy script's Proof V
 * compares it to the commit it shipped. An unset value must answer `null`,
 * never a made-up string, so a build that forgot to bake it reads as unknown.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { GET } from "./route";

afterEach(() => vi.unstubAllEnvs());

describe("GET /api/version", () => {
	it("returns the baked sha, no-store", async () => {
		vi.stubEnv("NEXT_PUBLIC_BUILD_SHA", "0123abcd");
		vi.stubEnv("NEXT_PUBLIC_BUILD_AT", "2026-09-14T16:00:00Z");
		const res = GET();
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(await res.json()).toEqual({
			sha: "0123abcd",
			built_at: "2026-09-14T16:00:00Z",
			surface: "web",
		});
	});

	it("answers null, not a fabricated value, when nothing was baked", async () => {
		vi.stubEnv("NEXT_PUBLIC_BUILD_SHA", "");
		vi.stubEnv("NEXT_PUBLIC_BUILD_AT", "");
		const body = (await GET().json()) as { sha: string | null };
		// "" is what an unset NEXT_PUBLIC_* folds to in some builds — still unknown.
		expect(body.sha === null || body.sha === "").toBe(true);
	});
});
