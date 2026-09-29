/** The /onboarding guard: signed-out → /sign-in; signed in (with or without an org) → the wizard. */
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	withAuth: vi.fn(),
	redirect: vi.fn((url: string) => {
		throw new Error(`NEXT_REDIRECT:${url}`);
	}),
}));
vi.mock("@workos-inc/authkit-nextjs", () => ({ withAuth: h.withAuth }));
vi.mock("next/navigation", () => ({ redirect: h.redirect }));
vi.mock("@/lib/e2e-auth", () => ({ e2eAuthEnabled: () => false }));

import OnboardingLayout from "./layout";

beforeEach(() => {
	h.withAuth.mockReset();
	h.redirect.mockClear();
});

describe("/onboarding guard", () => {
	it("an expired session ({ user: null }) goes to /sign-in", async () => {
		h.withAuth.mockResolvedValue({ user: null });
		await expect(OnboardingLayout({ children: "wizard" })).rejects.toThrow(
			"NEXT_REDIRECT:/sign-in",
		);
	});

	it("a withAuth failure is treated as signed out", async () => {
		h.withAuth.mockRejectedValue(new Error("cookies"));
		await expect(OnboardingLayout({ children: "wizard" })).rejects.toThrow(
			"NEXT_REDIRECT:/sign-in",
		);
	});

	it("a signed-in user with no org sees the wizard", async () => {
		h.withAuth.mockResolvedValue({
			user: { id: "u" },
			organizationId: undefined,
		});
		await expect(OnboardingLayout({ children: "wizard" })).resolves.toBe(
			"wizard",
		);
	});
});
