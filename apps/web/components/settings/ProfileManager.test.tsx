import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ signOutNow: vi.fn(), apiFetchRaw: vi.fn() }));
vi.mock("@/lib/sign-out", () => ({ signOutNow: h.signOutNow }));
vi.mock("@/lib/api-fetch", () => ({ apiFetchRaw: h.apiFetchRaw }));
import { ProfileManager } from "./ProfileManager";
afterEach(cleanup);
function mount() {
	render(
		<QueryClientProvider
			client={
				new QueryClient({ defaultOptions: { mutations: { retry: false } } })
			}
		>
			<ProfileManager
				initialName="Test"
				email="user@example.test"
				canDeleteOrg={false}
			/>
		</QueryClientProvider>,
	);
	fireEvent.change(screen.getByLabelText("confirm email"), {
		target: { value: "user@example.test" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));
}
it("deletion_sign_out_uses_helper", async () => {
	h.apiFetchRaw.mockResolvedValue(new Response());
	h.signOutNow.mockResolvedValue(undefined);
	mount();
	await waitFor(() => expect(h.signOutNow).toHaveBeenCalledTimes(1));
});
it("logout_retry_does_not_repeat_account_deletion", async () => {
	h.apiFetchRaw.mockResolvedValue(new Response());
	h.signOutNow
		.mockRejectedValueOnce(new Error())
		.mockResolvedValueOnce(undefined);
	mount();
	fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
	await waitFor(() => expect(h.signOutNow).toHaveBeenCalledTimes(2));
	expect(h.apiFetchRaw).toHaveBeenCalledTimes(1);
});
