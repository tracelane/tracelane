/**
 * Regression tests for the lazy Neon client (@/db).
 *
 * Guards the build-time defect where a module-scope
 * `neon(process.env.DATABASE_URL!)` forced the credential at *build* time and
 * broke `next build` when the env was absent. The client must be created on
 * FIRST USE: importing the module is side-effect-free, and a missing
 * `DATABASE_URL` surfaces only on first access, with a clear message.
 *
 * `vi.resetModules()` gives each case a fresh module (fresh client singleton).
 *
 * Each case re-imports `./index` (drizzle + @neondatabase/serverless) cold after
 * `vi.resetModules()`; vitest transforms that module graph on first import, which
 * can exceed the 5s default under `verify-all`'s parallel package load (it runs
 * warm at ~1.3s). These are transform-bound, not hanging — so they carry an
 * explicit 30s timeout (the repo pattern for legit-slow tests, cf. trace-tree).
 */

import { afterEach, describe, expect, it, vi } from "vitest";

const ORIG = process.env.DATABASE_URL;

afterEach(() => {
	if (ORIG === undefined) {
		Reflect.deleteProperty(process.env, "DATABASE_URL");
	} else {
		process.env.DATABASE_URL = ORIG;
	}
	vi.resetModules();
});

describe("@/db lazy client", () => {
	it("imports without DATABASE_URL set (no module-scope credential read)", async () => {
		Reflect.deleteProperty(process.env, "DATABASE_URL");
		vi.resetModules();
		await expect(import("./index")).resolves.toBeDefined();
	}, 30_000);

	it("throws a clear error only on first use when DATABASE_URL is unset", async () => {
		Reflect.deleteProperty(process.env, "DATABASE_URL");
		vi.resetModules();
		const { db } = await import("./index");
		expect(() => db.select).toThrow(/DATABASE_URL is not set/);
	}, 30_000);

	it("initialises the client on first use when DATABASE_URL is set", async () => {
		process.env.DATABASE_URL = "postgresql://u:p@db.example.com/neondb";
		vi.resetModules();
		const { db } = await import("./index");
		expect(typeof db.select).toBe("function");
	}, 30_000);
});
