/**
 * Tests for `upsertTenantId` name mirroring.
 *
 * Why: the nav workspace pill (`OrgSwitcher.tsx`) labels the workspace from one
 * cheap `tenants.name` read. That column had exactly ONE writer — the rename
 * endpoint — so a workspace that was never renamed kept an empty name forever
 * and every member saw the literal fallback "Workspace". The row is now named at
 * creation and healed if it predates that, which is what these tests pin.
 *
 * Negative case first per `.claude/rules/testing.md`: a stored name must never
 * be clobbered by a caller passing a stale one.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ db: null as DbMock | null }));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

import { upsertTenantId } from "./tenant";

const ORG = "org_test_123";
const TENANT_ID = "11111111-2222-3333-4444-555555555555";

function setDb(results: unknown[]): void {
	h.db = makeDbMock(results);
}

beforeEach(() => {
	h.db = null;
});

describe("upsertTenantId — name mirroring", () => {
	it("REJECT: never overwrites a name the rename endpoint already stored", async () => {
		setDb([[{ id: TENANT_ID, name: "Real Renamed Org" }]]);
		const id = await upsertTenantId(ORG, "stale-name-from-caller");
		expect(id).toBe(TENANT_ID);
		expect(h.db?.db.update).not.toHaveBeenCalled();
	});

	it("REJECT: no name supplied → existing empty name is left alone", async () => {
		setDb([[{ id: TENANT_ID, name: null }]]);
		const id = await upsertTenantId(ORG);
		expect(id).toBe(TENANT_ID);
		expect(h.db?.db.update).not.toHaveBeenCalled();
	});

	it("REJECT: a whitespace-only name is not treated as a name", async () => {
		setDb([[{ id: TENANT_ID, name: null }]]);
		await upsertTenantId(ORG, "   ");
		expect(h.db?.db.update).not.toHaveBeenCalled();
	});

	it("heals an EMPTY name on an existing row (pre-mirroring workspaces)", async () => {
		setDb([
			[{ id: TENANT_ID, name: null }], // existing row, never named
			[], // the healing update
		]);
		const id = await upsertTenantId(ORG, "demo");
		expect(id).toBe(TENANT_ID);
		expect(h.db?.db.update).toHaveBeenCalledTimes(1);
	});

	it("names the row at creation, so a fresh workspace is never nameless", async () => {
		setDb([
			[], // no existing row
			[{ id: TENANT_ID }], // insert ... returning
		]);
		const id = await upsertTenantId(ORG, "  demo  ");
		expect(id).toBe(TENANT_ID);
		expect(h.db?.db.insert).toHaveBeenCalledTimes(1);
	});

	it("a heal failure never breaks the caller (display cache only)", async () => {
		h.db = makeDbMock([[{ id: TENANT_ID, name: "" }]]);
		h.db.db.update = vi.fn(() => {
			throw new Error("postgres hiccup");
		});
		await expect(upsertTenantId(ORG, "demo")).resolves.toBe(TENANT_ID);
	});
});
