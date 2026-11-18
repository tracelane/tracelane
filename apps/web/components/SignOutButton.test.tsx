// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ signOutNow: vi.fn() }));
vi.mock("@/lib/sign-out", () => h);
import { SignOutButton } from "./SignOutButton";
afterEach(cleanup);
it("pending_button_blocks_duplicate_clicks", async () => {
	h.signOutNow.mockReturnValue(new Promise(() => {}));
	render(<SignOutButton />);
	fireEvent.click(screen.getByRole("button"));
	fireEvent.click(screen.getByRole("button"));
	expect(h.signOutNow).toHaveBeenCalledTimes(1);
	expect(screen.getByRole("button").textContent).toBe("Signing out…");
});
it("failed_logout_shows_retry_without_navigation", async () => {
	h.signOutNow
		.mockRejectedValueOnce(new Error())
		.mockResolvedValueOnce(undefined);
	render(<SignOutButton />);
	fireEvent.click(screen.getByRole("button"));
	await screen.findByRole("alert");
	fireEvent.click(screen.getByRole("button"));
	await waitFor(() => expect(h.signOutNow).toHaveBeenCalledTimes(2));
});
