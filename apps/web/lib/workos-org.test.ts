/**
 * Tests for the WorkOS org helper — cursor pagination (so a >100-row org can't
 * under-count) and the admin gate.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	callerIsOrgAdmin,
	getInvitationInOrg,
	listMemberships,
} from "./workos-org";

const KEY = "sk_test_workos_do_not_use";

afterEach(() => vi.unstubAllGlobals());

/** Two-page WorkOS list: page 1 carries an `after` cursor, page 2 ends it. */
function stubTwoPages(page1: unknown[], page2: unknown[]) {
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = args[0] as string;
		const onPage2 = url.includes("after=");
		return {
			ok: true,
			json: async () => ({
				data: onPage2 ? page2 : page1,
				list_metadata: { after: onPage2 ? null : "CURSOR" },
			}),
		} as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

describe("getInvitationInOrg — tenant isolation", () => {
	function stubInvite(orgId: string | undefined) {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					({
						ok: true,
						json: async () => ({
							id: "inv_1",
							email: "x@y.co",
							organization_id: orgId,
						}),
					}) as unknown as Response,
			),
		);
	}

	it("returns the invitation when it belongs to the caller's org", async () => {
		stubInvite("org_MINE");
		const inv = await getInvitationInOrg(KEY, "org_MINE", "inv_1");
		expect(inv?.id).toBe("inv_1");
	});

	it("returns null for an invitation in ANOTHER org (no existence leak)", async () => {
		stubInvite("org_SOMEONE_ELSE");
		expect(await getInvitationInOrg(KEY, "org_MINE", "inv_1")).toBeNull();
	});

	it("returns null when the lookup fails", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 404 }) as unknown as Response),
		);
		expect(await getInvitationInOrg(KEY, "org_MINE", "inv_x")).toBeNull();
	});
});

describe("listMemberships — cursor pagination", () => {
	it("follows list_metadata.after and concatenates every page", async () => {
		const spy = stubTwoPages([{ id: "a" }, { id: "b" }], [{ id: "c" }]);
		const all = await listMemberships(KEY, "org_1");
		expect(all?.map((m) => m.id)).toEqual(["a", "b", "c"]);
		// Two GETs — page 2 was fetched with the cursor.
		expect(spy).toHaveBeenCalledTimes(2);
		expect(spy.mock.calls[1]?.[0] as string).toContain("after=CURSOR");
	});

	it("returns null when a page request fails (callers fail closed)", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 500 }) as unknown as Response),
		);
		expect(await listMemberships(KEY, "org_1")).toBeNull();
	});
});

describe("callerIsOrgAdmin", () => {
	const members = (role: string) => [
		{ id: "m", user_id: "u1", organization_id: "org_1", role: { slug: role } },
	];
	const stubOnePage = (data: unknown[]) =>
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					({
						ok: true,
						json: async () => ({ data, list_metadata: { after: null } }),
					}) as unknown as Response,
			),
		);

	it("true for an admin caller, false for a member", async () => {
		stubOnePage(members("admin"));
		expect(await callerIsOrgAdmin(KEY, "org_1", "u1")).toBe(true);
		stubOnePage(members("member"));
		expect(await callerIsOrgAdmin(KEY, "org_1", "u1")).toBe(false);
	});

	it("false when the caller isn't in the org at all", async () => {
		stubOnePage(members("admin"));
		expect(await callerIsOrgAdmin(KEY, "org_1", "STRANGER")).toBe(false);
	});

	it("null when the lookup fails (fail closed)", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 500 }) as unknown as Response),
		);
		expect(await callerIsOrgAdmin(KEY, "org_1", "u1")).toBeNull();
	});
});
