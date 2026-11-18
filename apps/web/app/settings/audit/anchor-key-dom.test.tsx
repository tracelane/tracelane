// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import AuditKeyPage from "./page";

const h = vi.hoisted(() => ({ anchor: null as string | null, failure: false }));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "org_a" }),
}));
vi.mock("@/db", () => ({
	db: {
		select: () => ({
			from: () => ({
				where: () => ({
					limit: async () => {
						if (h.failure) throw new Error("private database details");
						return [
							{
								id: "workspace-a",
								ed: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
								anchor: h.anchor,
							},
						];
					},
				}),
			}),
		}),
	},
}));
const ANCHOR =
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==";
const writeText = vi.fn().mockResolvedValue(undefined);
beforeEach(() => {
	h.anchor = ANCHOR;
	h.failure = false;
	Object.defineProperty(navigator, "clipboard", {
		configurable: true,
		value: { writeText },
	});
});
afterEach(cleanup);
it("copies_exact_anchor_bytes", async () => {
	render(await AuditKeyPage());
	fireEvent.click(screen.getByRole("button", { name: "Copy anchor key" }));
	await waitFor(() => expect(writeText).toHaveBeenCalledWith(ANCHOR));
	expect(await screen.findByRole("button", { name: "Copied" })).toBeTruthy();
});
it("copy_signing_key_is_separate", async () => {
	render(await AuditKeyPage());
	fireEvent.click(screen.getByRole("button", { name: "Copy key" }));
	await waitFor(() =>
		expect(writeText).toHaveBeenCalledWith(
			"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		),
	);
});
it("absent_anchor_has_no_copy", async () => {
	h.anchor = null;
	render(await AuditKeyPage());
	expect(screen.getByText("No anchor key yet")).toBeTruthy();
	expect(screen.queryByRole("button", { name: "Copy anchor key" })).toBeNull();
});
it("failed_read_has_retry_not_empty", async () => {
	h.failure = true;
	render(await AuditKeyPage());
	expect(screen.getByText("Cannot determine anchor key")).toBeTruthy();
	expect(
		screen
			.getByRole("link", { name: "Reload audit keys" })
			.getAttribute("href"),
	).toBe("/settings/audit");
	expect(screen.queryByText("No anchor key yet")).toBeNull();
	expect(screen.queryByRole("button", { name: "Copy anchor key" })).toBeNull();
});
it("clipboard_denial_keeps_selectable_key", async () => {
	writeText.mockRejectedValueOnce(new Error("denied"));
	render(await AuditKeyPage());
	fireEvent.click(screen.getByRole("button", { name: "Copy anchor key" }));
	await waitFor(() => expect(writeText).toHaveBeenCalledWith(ANCHOR));
	expect(screen.getByText(ANCHOR).tagName).toBe("CODE");
	expect(screen.queryByRole("button", { name: "Copied" })).toBeNull();
});

it("offline_command_names_ed25519_key", async () => {
	render(await AuditKeyPage());
	expect(
		screen.getByText(
			"tlane verify ./audit.ndjson --tenant-pubkey <Ed25519 signing key>",
		),
	).toBeTruthy();
});
