/** ACT-41 — the approver re-authentication link and the forced-sign-in URL. */
import { describe, expect, it } from "vitest";
import { forceReauth, reauthHref } from "./step-up";

describe("forceReauth", () => {
	it("adds max_age=0 to the AuthKit authorize URL", () => {
		const u = new URL(
			forceReauth(
				"https://api.workos.com/user_management/authorize?client_id=c&state=s",
			),
		);
		expect(u.searchParams.get("max_age")).toBe("0");
		expect(u.searchParams.get("client_id")).toBe("c");
		expect(u.searchParams.get("state")).toBe("s");
	});
	it("overrides any max_age already present", () => {
		const u = new URL(forceReauth("https://a.example/authorize?max_age=900"));
		expect(u.searchParams.getAll("max_age")).toEqual(["0"]);
	});
	it("refuses a value that is not a URL rather than guessing", () => {
		expect(() => forceReauth("not a url")).toThrow();
	});
});

describe("reauthHref", () => {
	it("returns to the same approval after signing in", () => {
		expect(reauthHref("/actions/a1")).toBe(
			"/sign-in?reauth=1&returnTo=%2Factions%2Fa1",
		);
		expect(reauthHref("/settings/gateway/approvals?x=1")).toBe(
			"/sign-in?reauth=1&returnTo=%2Fsettings%2Fgateway%2Fapprovals%3Fx%3D1",
		);
	});
	it("drops an unsafe return path but still forces the sign-in", () => {
		for (const bad of [
			"//evil.example",
			"https://evil.example",
			"/api/x",
			"",
			"/\\evil",
		]) {
			expect(reauthHref(bad)).toBe("/sign-in?reauth=1");
		}
	});
});
