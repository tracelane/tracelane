import { describe, expect, it } from "vitest";
import { safeReturnTo } from "./return-to";

describe("safeReturnTo", () => {
	it("keeps a same-origin app path with its query", () => {
		expect(safeReturnTo("/traces?model=gpt-4o")).toBe("/traces?model=gpt-4o");
	});
	it("refuses open redirects and auth-route loops", () => {
		for (const bad of [
			"https://evil.example",
			"//evil.example",
			"/\\evil.example",
			"evil",
			"/sign-in",
			"/sign-in?returnTo=/x",
			"/sign-out",
			"/auth/callback",
			"/api/settings/model-aliases",
			"",
			null,
			undefined,
			`/${"a".repeat(3000)}`,
		]) {
			expect(safeReturnTo(bad), String(bad)).toBeUndefined();
		}
	});
});
