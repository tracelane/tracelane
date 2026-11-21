// @vitest-environment jsdom
import { cleanup, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { SlotView } from "./SlotView";
import { json, mockFetch, mount, when } from "./test-utils";

const row = (id: string, subject: string) => ({
	id,
	status: "pending",
	subject,
	subject_kind: "tool",
	server_name: "Mail",
	key_name: "Assistant",
	created_at: "2026-10-12T12:00:00Z",
	expires_at: "2026-10-12T12:15:00Z",
});
const A = "0b9a7f0e-5d55-4c3e-9a57-6a1f3e2c8d11";
const B = "1c0b8a1f-6e66-4d4f-8b68-7b2a4f3d9e22";
function reads() {
	return [
		when("GET", "/approvals", () =>
			json({
				approvals: [row(A, "send_email"), row(B, "delete_repo")],
				pending: 2,
			}),
		),
		when("GET", "/approvals/settings", () =>
			json({
				settings: { require_second_approver: false, default_ttl_secs: 900 },
				limits: { max_ttl_secs: 86400, note_max_chars: 500 },
			}),
		),
		when("GET", "/approval-rules", () => json({ rules: [] })),
	];
}
const slot = { id: "approvals", label: "Approvals", probe: "approvals" };
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	window.history.replaceState({}, "", "/");
});
function titleOf(name: string) {
	return screen.getByText(new RegExp(`^${name} ·`)).closest("li");
}
it("deeplink_highlights_only_the_linked_approval", async () => {
	window.history.replaceState({}, "", `/settings/gateway/approvals?id=${B}`);
	mockFetch(...reads());
	mount(<SlotView slot={slot} />);
	await screen.findByText(/^delete_repo ·/);
	expect(titleOf("delete_repo")?.getAttribute("aria-current")).toBe("true");
	expect(titleOf("send_email")?.getAttribute("aria-current")).toBeNull();
	expect(screen.queryByRole("status")).toBeNull();
});
it("deeplink_to_an_id_not_in_the_list_says_so", async () => {
	window.history.replaceState(
		{},
		"",
		"/settings/gateway/approvals?id=ffffffff-0000-4000-8000-000000000000",
	);
	mockFetch(...reads());
	mount(<SlotView slot={slot} />);
	await screen.findByText(/^send_email ·/);
	expect((await screen.findByRole("status")).textContent).toMatch(
		/not in this list/,
	);
	expect(titleOf("send_email")?.getAttribute("aria-current")).toBeNull();
});
it("no_id_means_no_highlight_and_no_note", async () => {
	mockFetch(...reads());
	mount(<SlotView slot={slot} />);
	await screen.findByText(/^send_email ·/);
	expect(document.querySelector("[aria-current]")).toBeNull();
	expect(screen.queryByRole("status")).toBeNull();
});
