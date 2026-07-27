import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isChunkLoadError, reloadOnChunkError } from "./chunk-reload";

describe("isChunkLoadError", () => {
	it("matches a ChunkLoadError by name", () => {
		const e = new Error("boom");
		e.name = "ChunkLoadError";
		expect(isChunkLoadError(e)).toBe(true);
	});
	it("matches known skew messages", () => {
		for (const m of [
			"Loading chunk 4821 failed.",
			"Failed to fetch dynamically imported module: https://app/_next/x.js",
			"error loading dynamically imported module",
			"importing a module script failed.",
		]) {
			expect(isChunkLoadError(new Error(m))).toBe(true);
		}
	});
	it("REJECTS an ordinary runtime error (must not reload on a real bug)", () => {
		expect(
			isChunkLoadError(new Error("Cannot read properties of undefined")),
		).toBe(false);
		expect(isChunkLoadError("a string")).toBe(false);
		expect(isChunkLoadError(null)).toBe(false);
	});
});

describe("reloadOnChunkError", () => {
	let reload: ReturnType<typeof vi.fn>;
	let store: Record<string, string>;
	beforeEach(() => {
		reload = vi.fn();
		store = {};
		// node env (no DOM) — stub the minimal browser surface the util touches.
		vi.stubGlobal("window", {
			location: { reload },
			sessionStorage: {
				getItem: (k: string) => store[k] ?? null,
				setItem: (k: string, v: string) => {
					store[k] = v;
				},
			},
		});
	});
	afterEach(() => vi.unstubAllGlobals());

	it("hard-reloads once on a chunk error and returns true", () => {
		expect(reloadOnChunkError(new Error("Loading chunk 12 failed."))).toBe(
			true,
		);
		expect(reload).toHaveBeenCalledTimes(1);
	});

	it("does NOT reload on a non-chunk error (returns false → normal boundary)", () => {
		expect(
			reloadOnChunkError(new Error("TypeError: x is not a function")),
		).toBe(false);
		expect(reload).not.toHaveBeenCalled();
	});

	it("LOOP GUARD: a second chunk error within the window does not reload again", () => {
		const e = new Error("Loading chunk 12 failed.");
		expect(reloadOnChunkError(e)).toBe(true); // 1st: reloads
		expect(reloadOnChunkError(e)).toBe(false); // 2nd (reload didn't help) → boundary
		expect(reload).toHaveBeenCalledTimes(1);
	});

	it("no-ops during SSR (no window) → false", () => {
		vi.stubGlobal("window", undefined);
		expect(reloadOnChunkError(new Error("Loading chunk 1 failed."))).toBe(
			false,
		);
	});
});
