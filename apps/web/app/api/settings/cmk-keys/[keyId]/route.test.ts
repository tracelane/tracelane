/**
 * Tests for DELETE /api/settings/cmk-keys/[keyId] (revoke).
 *
 * Focus: the admin gate (2026-07-22 audit — any member/viewer could revoke
 * the tenant's active CMK, degrading encryption posture for the whole org).
 * Negative first per .claude/rules/testing.md.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as DbMock | null,
	session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
	isAdmin: true as boolean | null,
	recordAdminAction: vi.fn(async (_entry: unknown) => undefined),
}));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => h.session),
}));

vi.mock("@/lib/workos-org", () => ({
	callerIsOrgAdmin: vi.fn(async () => h.isAdmin),
}));

vi.mock("@/lib/admin-audit", () => ({
	recordAdminAction: h.recordAdminAction,
	ipFromRequest: () => null,
}));

import { DELETE } from "./route";

function setDb(results: unknown[]): DbMock {
	const m = makeDbMock(results);
	h.db = m;
	return m;
}

const params = { params: Promise.resolve({ keyId: "cmk-1" }) };
const req = { headers: new Headers() } as unknown as NextRequest;

describe("DELETE /api/settings/cmk-keys/[keyId]", () => {
	beforeEach(() => {
		h.isAdmin = true;
		vi.stubEnv("WORKOS_API_KEY", "sk_test_workos_unit_only");
	});
	afterEach(() => vi.unstubAllEnvs());

	it("REJECT: a member/viewer revoke is 403 and the DB is never touched", async () => {
		h.isAdmin = false;
		const m = setDb([]);
		const res = await DELETE(req, params);
		expect(res.status).toBe(403);
		expect(m.cursor()).toBe(0);
	});

	it("REJECT: role lookup failure fails CLOSED with 502", async () => {
		h.isAdmin = null;
		const m = setDb([]);
		const res = await DELETE(req, params);
		expect(res.status).toBe(502);
		expect(m.cursor()).toBe(0);
	});

	it("HAPPY: an admin revokes a key (204) and the action is audited", async () => {
		setDb([
			[{ id: "tenant-db-uuid" }], // tenant lookup
			[{ id: "cmk-1", alias: "prod", fingerprint: "ab".repeat(32) }], // update returning
		]);
		const res = await DELETE(req, params);
		expect(res.status).toBe(204);
		// ADR-031: the revoke leaves an audit row.
		expect(h.recordAdminAction).toHaveBeenCalledTimes(1);
	});
});
