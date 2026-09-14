/**
 * Tests for the `isOrgArchived` memoization (B-361).
 *
 * PROBLEM: `isOrgArchived` ran a live Neon query on EVERY authenticated
 * request via `requireSession`. One open dashboard tab fired it every few
 * seconds, which is why Neon's Operations log showed the compute waking every
 * 5-15 minutes at zero users. This caches the result per `workosOrgId` for
 * `TRACELANE_ORG_ARCHIVED_TTL_MS` (default 15 min, longer than Neon's 5-min
 * autosuspend), fail-open unchanged: only a POSITIVE read is cached, never an
 * error.
 *
 * `withAuth`, `next/navigation`'s `redirect`, and `@/db` are all mocked — no
 * real network, no real Postgres, per `.claude/rules/testing.md`. Negative
 * case (an error must NOT be cached) is written before the happy-path TTL
 * case per the same rule.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type DbMock, makeDbMock } from "./__testutils__/db-mock";

// Hoisted doubles so the vi.mock factories can reach them.
const h = vi.hoisted(() => ({
	withAuth: vi.fn(),
	redirect: vi.fn((url: string) => {
		throw new Error(`NEXT_REDIRECT:${url}`);
	}),
	dbCurrent: null as DbMock | null,
}));

vi.mock("@workos-inc/authkit-nextjs", () => ({ withAuth: h.withAuth }));
vi.mock("next/navigation", () => ({ redirect: h.redirect }));
vi.mock("@/db", () => ({
	get db() {
		if (!h.dbCurrent) throw new Error("db mock not initialised");
		return h.dbCurrent.db;
	},
}));

const ORG_ID = "org_b361_test";

/** Queue the db.select results `isOrgArchived` will consume, in order. */
function setDbResults(results: unknown[]): DbMock {
	const m = makeDbMock(results);
	h.dbCurrent = m;
	return m;
}

/** A row shaped like the real `tenants.archivedAt` select. */
function row(archivedAt: Date | null): unknown[] {
	return archivedAt === null ? [] : [{ archivedAt }];
}

async function freshRequireSession() {
	vi.resetModules();
	h.withAuth.mockReset();
	h.redirect.mockClear();
	h.withAuth.mockResolvedValue({
		user: { id: "user_1", email: "user@example.com" },
		organizationId: ORG_ID,
		role: "owner",
	});
	const mod = await import("./auth");
	return mod.requireSession;
}

beforeEach(() => {
	vi.stubEnv("NODE_ENV", "test"); // !== production
	vi.stubEnv("TRACELANE_ORG_ARCHIVED_TTL_MS", "");
	h.dbCurrent = null;
});

afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllEnvs();
	vi.resetModules();
});

describe("isOrgArchived memoization (via requireSession)", () => {
	// Negative case first (.claude/rules/testing.md): an error must NOT be
	// cached, so the very next call re-reads rather than being pinned to a
	// stale answer for the whole TTL.
	it("REJECT: a DB error is not cached — the next call reads again", async () => {
		const requireSession = await freshRequireSession();
		const db = setDbResults([new Error("Postgres unavailable"), row(null)]);

		// Error → fail-open: isOrgArchived swallows it and returns false, so
		// the request proceeds (no redirect to /organization-deleted).
		const s1 = await requireSession();
		expect(s1.tenantId).toBe(ORG_ID);
		expect(db.db.select).toHaveBeenCalledTimes(1);

		// Not cached: the second call issues a SECOND db read.
		const s2 = await requireSession();
		expect(s2.tenantId).toBe(ORG_ID);
		expect(db.db.select).toHaveBeenCalledTimes(2);
	});

	it("two calls within the TTL issue exactly ONE db read", async () => {
		const requireSession = await freshRequireSession();
		const db = setDbResults([row(null), row(null)]); // 2nd never consumed if cached

		await requireSession();
		await requireSession();

		expect(db.db.select).toHaveBeenCalledTimes(1);
	});

	it("after the TTL elapses, the next call issues a SECOND db read", async () => {
		vi.stubEnv("TRACELANE_ORG_ARCHIVED_TTL_MS", "1000");
		vi.useFakeTimers();
		const requireSession = await freshRequireSession();
		const db = setDbResults([row(null), row(null)]);

		await requireSession();
		expect(db.db.select).toHaveBeenCalledTimes(1);

		vi.advanceTimersByTime(1001);

		await requireSession();
		expect(db.db.select).toHaveBeenCalledTimes(2);
	});

	it("invalidateOrgArchivedCache forces a re-read even INSIDE the TTL", async () => {
		vi.resetModules();
		h.withAuth.mockReset();
		h.redirect.mockClear();
		h.withAuth.mockResolvedValue({
			user: { id: "user_1", email: "user@example.com" },
			organizationId: ORG_ID,
			role: "owner",
		});
		const { requireSession, invalidateOrgArchivedCache } = await import(
			"./auth"
		);
		const db = setDbResults([row(null), row(null)]);

		await requireSession();
		expect(db.db.select).toHaveBeenCalledTimes(1);

		invalidateOrgArchivedCache(ORG_ID);

		await requireSession();
		expect(db.db.select).toHaveBeenCalledTimes(2);
	});

	it("archived=true is cached too — one read serves both redirecting calls", async () => {
		const requireSession = await freshRequireSession();
		const db = setDbResults([row(new Date("2026-01-01T00:00:00Z"))]);

		await expect(requireSession()).rejects.toThrow(
			/NEXT_REDIRECT:\/organization-deleted/,
		);
		await expect(requireSession()).rejects.toThrow(
			/NEXT_REDIRECT:\/organization-deleted/,
		);

		expect(db.db.select).toHaveBeenCalledTimes(1);
		expect(h.redirect).toHaveBeenCalledWith("/organization-deleted");
	});
});
