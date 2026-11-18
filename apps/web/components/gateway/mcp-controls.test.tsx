// @vitest-environment jsdom
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { SlotView } from "./SlotView";
import { json, mockFetch, mount, when } from "./test-utils";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
const policy = {
	policy: {
		rules_mode: "observe",
		pins_mode: "observe",
		injection_mode: "observe",
		default_action: "allow",
	},
	rules: [],
	model_rules: [],
	limits: { tool_glob_max_chars: 128, reason_max_chars: 200 },
};
it("mcp_policy_form_saves_real_controls", async () => {
	const { calls } = mockFetch(
		when("GET", "/mcp-policy", () => json(policy)),
		when("GET", "/mcp-servers", () => json({ servers: [], limits: {} })),
		when("GET", "/mcp-tools", () => json({ tools: [] })),
		when("PUT", "/mcp-policy", () => json(policy.policy)),
	);
	mount(
		<SlotView slot={{ id: "mcp", label: "MCP tools", probe: "mcp-policy" }} />,
	);
	fireEvent.change(await screen.findByLabelText("Tool rules"), {
		target: { value: "enforce" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save tool policy" }));
	await waitFor(() =>
		expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
			...policy.policy,
			rules_mode: "enforce",
		}),
	);
});
it("approval_queue_renders_real_controls", async () => {
	const { calls } = mockFetch(
		when("GET", "/approvals", () =>
			json({
				approvals: [
					{
						id: "a",
						status: "pending",
						subject: "send_email",
						subject_kind: "tool",
						server_name: "Mail",
						key_name: "Assistant",
						created_at: "2026-10-12T12:00:00Z",
						expires_at: "2026-10-12T12:15:00Z",
					},
				],
				pending: 1,
			}),
		),
		when("GET", "/approvals/settings", () =>
			json({
				settings: { require_second_approver: false, default_ttl_secs: 900 },
				limits: { max_ttl_secs: 86400, note_max_chars: 500 },
			}),
		),
		when("GET", "/approval-rules", () => json({ rules: [] })),
		when("POST", "/approvals/a/approve", () => json({ status: "approved" })),
	);
	mount(
		<SlotView
			slot={{ id: "approvals", label: "Approvals", probe: "approvals" }}
		/>,
	);
	fireEvent.click(
		await screen.findByRole("button", { name: "Approve send_email" }),
	);
	await waitFor(() =>
		expect(
			calls.some(
				(c) => c.method === "POST" && c.url.endsWith("/approvals/a/approve"),
			),
		).toBe(true),
	);
});
const mcpSlot = { id: "mcp", label: "MCP tools", probe: "mcp-policy" };
const approvalsSlot = {
	id: "approvals",
	label: "Approvals",
	probe: "approvals",
};
function mcpReads() {
	return [
		when("GET", "/mcp-policy", () => json({ ...policy, keys: [] })),
		when("GET", "/mcp-servers", () => json({ servers: [], limits: {} })),
		when("GET", "/mcp-tools", () => json({ tools: [] })),
		when("GET", "/mcp-policy/preview", () =>
			json({ would_block: null, stats_unavailable: true }),
		),
	];
}
it("mcp_read_only_role_hides_mutations", async () => {
	mockFetch(...mcpReads());
	mount(<SlotView slot={mcpSlot} />, "developer");
	await screen.findByText("MCP servers");
	expect(screen.queryByRole("button", { name: "Save tool policy" })).toBeNull();
	expect(screen.queryByRole("button", { name: "Add server" })).toBeNull();
});
it("mcp_unknown_preview_is_not_zero", async () => {
	mockFetch(...mcpReads());
	mount(<SlotView slot={mcpSlot} />);
	await screen.findByText(/Policy preview is unavailable/);
	expect(screen.queryByText(/0 calls would/)).toBeNull();
});
it("mcp_policy_write_failure_preserves_edit", async () => {
	mockFetch(
		...mcpReads(),
		when("PUT", "/mcp-policy", () =>
			json({ error: "policy_unavailable" }, 503),
		),
	);
	mount(<SlotView slot={mcpSlot} />);
	const select = await screen.findByLabelText("Tool rules");
	fireEvent.change(select, { target: { value: "enforce" } });
	fireEvent.click(screen.getByRole("button", { name: "Save tool policy" }));
	await screen.findByRole("alert");
	expect((select as HTMLSelectElement).value).toBe("enforce");
});
it("mcp_fetch_failure_has_retry", async () => {
	mockFetch(
		when("GET", "/mcp-policy", () => json({ error: "unavailable" }, 503)),
	);
	mount(<SlotView slot={mcpSlot} />);
	await screen.findAllByRole("button", { name: "Retry" });
	expect(screen.queryByRole("button", { name: "Save tool policy" })).toBeNull();
});
it("mcp_forbidden_fetch_does_not_render_controls", async () => {
	mockFetch(
		when("GET", "/mcp-policy", () => json({ error: "forbidden" }, 403)),
	);
	mount(<SlotView slot={mcpSlot} />);
	await screen.findAllByRole("alert");
	expect(screen.queryByRole("button", { name: "Save tool policy" })).toBeNull();
});
it("approval_empty_queue_explains_status", async () => {
	mockFetch(
		when("GET", "/approvals", () =>
			json({ approvals: [], pending: 0, next_cursor: null }),
		),
	);
	mount(<SlotView slot={approvalsSlot} />, "developer");
	await screen.findByText("No pending requests.");
	expect(screen.queryByRole("button", { name: /Approve / })).toBeNull();
});
it("approval_status_filter_requests_selected_status", async () => {
	const { calls } = mockFetch(
		when("GET", "/approvals", () =>
			json({ approvals: [], pending: 0, next_cursor: null }),
		),
	);
	mount(<SlotView slot={approvalsSlot} />, "developer");
	fireEvent.change(await screen.findByLabelText("Approval status"), {
		target: { value: "denied" },
	});
	await screen.findByText("No denied requests.");
	expect(calls.some((c) => c.url.includes("status=denied"))).toBe(true);
});
it("approval_model_rule_saves_key_and_lifetime", async () => {
	const { calls } = mockFetch(
		when("GET", "/approvals", () =>
			json({ approvals: [], pending: 0, next_cursor: null }),
		),
		when("GET", "/approval-rules", () =>
			json({
				rules: [],
				keys: [{ id: "key-a", name: "Build agent" }],
				limits: { tool_glob_max_chars: 128, max_ttl_secs: 86400 },
			}),
		),
		when("POST", "/approval-rules", () => json({ id: "rule" })),
	);
	mount(<SlotView slot={approvalsSlot} />);
	fireEvent.change(await screen.findByLabelText("Model pattern"), {
		target: { value: "gpt-*" },
	});
	fireEvent.change(screen.getByLabelText("Model rule key"), {
		target: { value: "key-a" },
	});
	fireEvent.change(screen.getByLabelText("Rule lifetime (seconds, optional)"), {
		target: { value: "120" },
	});
	fireEvent.click(
		screen.getByRole("button", { name: "Add model approval rule" }),
	);
	await waitFor(() =>
		expect(calls.find((c) => c.method === "POST")?.body).toEqual({
			model_glob: "gpt-*",
			key_id: "key-a",
			ttl_secs: 120,
		}),
	);
});

it("approval_argument_preview_uses_labelled_fields", async () => {
	const preview = JSON.stringify({
		recipient: "ops@example.invalid",
		message: "Ready for review",
	});
	mockFetch(
		when("GET", "/approvals", () =>
			json({
				approvals: [
					{
						id: "a",
						status: "pending",
						subject: "send_email",
						subject_kind: "tool",
						key_name: "Assistant",
						created_at: "2026-10-12T12:00:00Z",
						expires_at: "2026-10-12T12:15:00Z",
						args_preview: preview,
					},
				],
				pending: 1,
				next_cursor: null,
			}),
		),
	);
	mount(<SlotView slot={approvalsSlot} />);
	await screen.findByText("recipient");
	expect(screen.getByText("ops@example.invalid")).toBeTruthy();
	expect(screen.getByText("Ready for review")).toBeTruthy();
	expect(screen.queryByText(preview)).toBeNull();
});
