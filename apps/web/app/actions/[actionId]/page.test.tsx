// @vitest-environment jsdom
import { json, mockFetch, mount, when } from "@/components/gateway/test-utils";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

vi.mock("@/components/gateway/RoleScope", () => ({
	RoleScope: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
const refresh = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh }),
}));
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(),
	requireSession: async () => ({ role: "owner" }),
}));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
}));
import { GatewayError, gatewayGet } from "@/lib/gateway";
import Page from "./page";

const ev = (seq: number, event_type: string, body = {}) => ({
	seq,
	event_type,
	occurred_at: "2026-11-09T10:42:03Z",
	actor_kind: "system",
	body,
});
const detail = (over: Record<string, unknown> = {}) => ({
	action_id: "a1",
	// deliberately out of order: the page must sort by seq
	events: [
		// Field names match the signed payload (verifier-rust ActionPayload::DecisionMade).
		ev(1043, "decision_made", {
			decision: "require_approval",
			rule_id: "approval-above-5k",
			policy_version: 3,
		}),
		ev(1042, "action_proposed"),
		ev(1044, "approval_requested"),
	],
	descriptor_digest: "dig-1",
	approval: {
		approval_id: "ap1",
		status: "pending",
		tool_name: "release_payment",
		server_id: "payments-mock",
		policy_id: "pay-001",
		policy_version: 3,
		policy_hash: "9c1e44a0b2f3deadbeef0011",
		proposer_key_id: "3f..a1",
		expires_at: "2026-11-09T10:57:00Z",
		evidence_fields: {
			amount: { mode: "clear", value: { MinorUnits: 1500000 } },
			currency: { mode: "clear", value: { Currency: "USD" } },
			beneficiary_id: { mode: "tokenize", hmac: "SECRET-HMAC", last4: "T001" },
			memo: { mode: "digest_only", sha256: "SECRET-SHA" },
		},
	},
	...over,
});
const render = async (role: string | null = "owner") =>
	mount(await Page({ params: Promise.resolve({ actionId: "a1" }) }), role);
afterEach(cleanup);
beforeEach(() => {
	vi.resetAllMocks();
	vi.mocked(gatewayGet).mockResolvedValue(detail());
});

it("renders timeline in seq order", async () => {
	await render();
	const text = document.body.textContent ?? "";
	const at = (s: string) => text.indexOf(s);
	expect(at("Proposed by an agent")).toBeGreaterThan(-1);
	expect(at("Proposed by an agent")).toBeLessThan(at("Policy decision"));
	expect(at("Policy decision")).toBeLessThan(at("Approval requested"));
	expect(text).toContain("#1042");
	// The decision line reads the signed payload's own field names; a guessed name renders blank.
	expect(text).toContain("Decision require approval");
	expect(text).toContain("rule approval-above-5k");
	expect(text).toContain("policy v3");
});
it("renders full bound descriptor", async () => {
	await render();
	const text = document.body.textContent ?? "";
	for (const t of [
		"release_payment",
		"payments-mock",
		"pay-001",
		"9c1e44a0b2f3",
		"3f..a1",
		"$15,000.00",
		"•••• T001",
		"shown",
		"tokenized — last 4",
		"hidden — digest only",
	])
		expect(text).toContain(t);
});
it("approve posts descriptor digest", async () => {
	const { calls } = mockFetch(
		when("POST", "approvals/ap1/approve", () => json({})),
	);
	await render();
	fireEvent.click(screen.getByRole("button", { name: "Approve" }));
	await waitFor(() => expect(calls).toHaveLength(1));
	expect(calls[0]?.body).toMatchObject({ descriptor_digest: "dig-1" });
});
it("deny posts descriptor digest", async () => {
	const { calls } = mockFetch(
		when("POST", "approvals/ap1/deny", () => json({})),
	);
	await render();
	fireEvent.click(screen.getByRole("button", { name: "Deny" }));
	await waitFor(() => expect(calls).toHaveLength(1));
	expect(calls[0]?.url).toContain("approvals/ap1/deny");
	expect(calls[0]?.body).toMatchObject({ descriptor_digest: "dig-1" });
});
it("links evidence download", async () => {
	await render();
	const a = screen.getByRole("link", { name: "Download evidence" });
	expect(a.getAttribute("href")).toBe("/api/audit/export");
	expect(document.body.textContent).toContain("Verify offline with");
});
it("renders not found", async () => {
	vi.mocked(gatewayGet).mockRejectedValue(new GatewayError(404, "nf"));
	await render();
	expect(document.body.textContent).toContain(
		"This action doesn't exist in this workspace.",
	);
});
it("hides decision buttons without capability", async () => {
	await render("viewer");
	expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
	expect(screen.queryByRole("button", { name: "Deny" })).toBeNull();
	expect(document.body.textContent).toContain("release_payment");
});
it("shows separation refusal message", async () => {
	mockFetch(
		when("POST", "approvals/ap1/approve", () =>
			json({ error: "separation_required" }, 403),
		),
	);
	await render();
	fireEvent.click(screen.getByRole("button", { name: "Approve" }));
	expect(
		await screen.findByText(
			"You created this agent key or published this policy, so you can't approve it.",
		),
	).toBeTruthy();
});
it("handles descriptor mismatch", async () => {
	mockFetch(
		when("POST", "approvals/ap1/deny", () =>
			json({ error: "descriptor_mismatch" }, 409),
		),
	);
	await render();
	fireEvent.click(screen.getByRole("button", { name: "Deny" }));
	expect(
		await screen.findByText("This request changed. Review it again."),
	).toBeTruthy();
});
it("renders unknown event type safely", async () => {
	vi.mocked(gatewayGet).mockResolvedValue(
		detail({ events: [ev(1, "teleported_somewhere")], approval: null }),
	);
	await render();
	expect(document.body.textContent).toContain("Event: teleported_somewhere");
});
it("never renders digest-only values", async () => {
	await render();
	expect(document.body.textContent).not.toContain("SECRET-SHA");
	expect(document.body.innerHTML).not.toContain("SECRET-SHA");
	expect(document.body.innerHTML).not.toContain("SECRET-HMAC");
});
it("shows expiry on the approval request line and a labelled status", async () => {
	await render();
	const text = document.body.textContent ?? "";
	expect(text).toContain("expires Nov 9, 2026 · 10:57 UTC");
	expect(text).toContain("Pending");
});
it("refreshes with an expiry notice on approval_expired", async () => {
	mockFetch(
		when("POST", "approvals/ap1/approve", () =>
			json({ error: "approval_expired" }, 409),
		),
	);
	await render();
	refresh.mockClear();
	fireEvent.click(screen.getByRole("button", { name: "Approve" }));
	expect(await screen.findByText("This request expired.")).toBeTruthy();
	// The panel must reload the authoritative state, not just show text.
	await waitFor(() => expect(refresh).toHaveBeenCalled());
});
it("explains a pending approval that has no descriptor digest", async () => {
	vi.mocked(gatewayGet).mockResolvedValue(detail({ descriptor_digest: null }));
	await render();
	expect(document.body.textContent).toContain(
		"This request can't be decided from this view.",
	);
	expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
});

it("keeps the timeline when retention cleared the bound request", async () => {
	vi.mocked(gatewayGet).mockResolvedValue(
		detail({ approval: null, descriptor_digest: null, approval_expired: true }),
	);
	await render();
	const text = document.body.textContent ?? "";
	expect(text).toContain("Proposed by an agent");
	expect(text).toContain("past retention");
	expect(text).not.toContain("Bound request");
	expect(screen.queryByRole("button", { name: /approve/i })).toBeNull();
});
