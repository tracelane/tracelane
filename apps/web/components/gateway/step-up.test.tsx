import { describeRefusal } from "@/lib/gateway-controls";
// @vitest-environment jsdom
/** ACT-41 — a stale sign-in on Approve offers "Sign in again" back to this page. */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { ControlError, RefusalNote } from "./control";

afterEach(cleanup);

const err = (status: number, body: Record<string, unknown>) =>
	new ControlError(status, describeRefusal(status, body), body);

it("offers a sign-in link that returns to the same page", () => {
	window.history.replaceState(null, "", "/actions/a1?tab=x");
	render(
		<RefusalNote
			error={err(403, { error: "reauth_required", max_age_secs: 900 })}
		/>,
	);
	expect(screen.getByRole("alert").textContent).toContain(
		"Approving needs a sign-in from the last 15 minutes.",
	);
	const link = screen.getByRole("link", { name: "Sign in again" });
	expect(link.getAttribute("href")).toBe(
		"/sign-in?reauth=1&returnTo=%2Factions%2Fa1%3Ftab%3Dx",
	);
});

it("shows no sign-in link for any other refusal", () => {
	for (const [s, b] of [
		[403, { error: "forbidden" }],
		[403, { error: "separation_required" }],
		[403, { error: "sso_required" }],
		[409, { error: "approval_expired" }],
		[503, { error: "approval_unavailable" }],
	] as const) {
		const { unmount } = render(<RefusalNote error={err(s, { ...b })} />);
		expect(screen.queryByRole("link", { name: "Sign in again" })).toBeNull();
		unmount();
	}
});
