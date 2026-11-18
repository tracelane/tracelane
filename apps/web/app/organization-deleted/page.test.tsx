// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
	signOutNow: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("@/lib/sign-out", () => h);
import Page from "./page";
afterEach(cleanup);
it("org_deleted_sign_out_uses_helper", () => {
	render(<Page />);
	fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
	expect(h.signOutNow).toHaveBeenCalledTimes(1);
});

it("distinguishes purge eligibility from completed deletion and retained data", () => {
	const html = renderToStaticMarkup(<Page />);
	expect(html).not.toContain("permanent deletion within 30 days");
	expect(html).toContain("eligible for purge");
	expect(html).toContain("30-day grace period by default");
	expect(html).toContain("Audit records and backups");
	expect(html).toContain('aria-label="Sign out"');
});
