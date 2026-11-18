// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
	signOutNow: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("@/lib/sign-out", () => h);
import { EmailChangeForm } from "./EmailChangeForm";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
it("email_change_sign_out_uses_helper", async () => {
	vi.stubGlobal(
		"fetch",
		vi
			.fn()
			.mockResolvedValue(
				Response.json({ email: "new@example.test", verificationSent: true }),
			),
	);
	render(<EmailChangeForm email="old@example.test" />);
	for (const [label, value] of [
		["New email", "new@example.test"],
		["New email again", "new@example.test"],
		["Type your current email to confirm", "old@example.test"],
	] as const)
		fireEvent.change(screen.getByLabelText(label), { target: { value } });
	fireEvent.click(screen.getByRole("button", { name: "Change email" }));
	fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
	expect(h.signOutNow).toHaveBeenCalledTimes(1);
});
