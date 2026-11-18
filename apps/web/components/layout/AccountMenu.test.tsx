// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
	signOutNow: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("@/lib/sign-out", () => h);
import { AccountMenu } from "./AccountMenu";
afterEach(cleanup);
it("menu_sign_out_uses_helper", () => {
	const { container } = render(<AccountMenu />);
	container.querySelector("details")?.setAttribute("open", "");
	fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
	expect(h.signOutNow).toHaveBeenCalledTimes(1);
});
