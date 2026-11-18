// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	act,
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Approvals } from "./Approvals";
import { DataControls } from "./DataControls";
import { McpControls } from "./McpControls";
import { RoleProvider } from "./control";
import { json, mockFetch, mount, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const dataView = {
	retention: {
		days: null,
		effective_days: 730,
		plan_days: 730,
		min_days: 7,
		max_days: 730,
	},
	sweep: { mode: "off", enforced: false, next_sweep_at: null },
	key_overrides_count: 0,
	routes: [],
};
const policyView = {
	policy: {
		rules_mode: "observe",
		pins_mode: "observe",
		injection_mode: "observe",
		default_action: "allow",
	},
	rules: [],
	keys: [],
	limits: {
		tool_glob_max_chars: 128,
		reason_max_chars: 200,
		preview_window_hours: 24,
		preview_max_window_hours: 168,
	},
};
const serverLimits = {
	max_servers_per_workspace: 20,
	max_name_chars: 256,
	max_slug_chars: 48,
	max_url_bytes: 2048,
};
const approval = {
	id: "11111111-1111-4111-8111-111111111111",
	status: "pending",
	subject: "send_email",
	subject_kind: "tool",
	server_name: "Mail",
	key_name: "Assistant",
	requester_sub: "apikey:private-requester-id",
	created_at: "2026-10-12T12:00:00Z",
	expires_at: "2026-10-12T12:15:00Z",
};
function captureRead() {
	return when("GET", "/api/settings/content-capture", () =>
		json({
			input: false,
			output: false,
			operator_allowlisted: false,
			effective: { input: false, output: false },
			queryable_days: 730,
			max_field_bytes: 65536,
			can_edit: true,
		}),
	);
}
function mcpReads() {
	return [
		when("GET", "/mcp-policy", () => json(policyView)),
		when("GET", "/mcp-servers", () =>
			json({ servers: [], limits: serverLimits }),
		),
		when("GET", "/mcp-tools", () => json({ tools: [] })),
		when("GET", "/mcp-policy/preview", () =>
			json({ would_block: null, stats_unavailable: true }),
		),
	];
}
function approvalSettings() {
	return [
		when("GET", "/approvals/settings", () =>
			json({
				settings: { require_second_approver: false, default_ttl_secs: 900 },
				limits: { max_ttl_secs: 86400, note_max_chars: 500 },
			}),
		),
		when("GET", "/approval-rules", () =>
			json({
				rules: [],
				keys: [],
				limits: { tool_glob_max_chars: 128, max_ttl_secs: 86400 },
			}),
		),
	];
}

it("og38_key_capture_refetch_preserves_new_response_constraint_when_input_is_saved", async () => {
	const keyId = "22222222-2222-4222-8222-222222222222";
	let capture: { input?: boolean; output?: boolean } | null = null;
	const { calls } = mockFetch(
		when("GET", "/data-controls", () =>
			json({
				...dataView,
				keys: [
					{ id: keyId, name: "Build agent", prefix: "tlane_test", capture },
				],
			}),
		),
		captureRead(),
		when("PATCH", `/keys/${keyId}`, () => json({ changed: ["capture"] })),
	);
	const { client } = mount(<DataControls />);
	await screen.findByLabelText("Disable response capture for this key");
	// Another editor narrows this same key; exercise the real refetch, preserving its id.
	capture = { output: false };
	await act(async () => {
		await client.invalidateQueries({
			queryKey: ["gateway-control", "data-controls"],
		});
	});
	await waitFor(() =>
		expect(
			client.getQueryData<{ keys: { capture: unknown }[] }>([
				"gateway-control",
				"data-controls",
			])?.keys[0]?.capture,
		).toEqual({ output: false }),
	);
	fireEvent.click(screen.getByLabelText("Disable prompt capture for this key"));
	fireEvent.click(screen.getByRole("button", { name: "Save key capture" }));
	await waitFor(() =>
		expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
			capture: { input: false, output: false },
		}),
	);
	expect(
		(
			screen.getByLabelText(
				"Disable response capture for this key",
			) as HTMLInputElement
		).checked,
	).toBe(true);
});

it("mcp_viewer_cannot_render_cached_server_urls_or_mutation_controls", async () => {
	const privateUrl = "https://tools.example.invalid/private-path-token";
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	client.setQueryData(["gateway-control", "mcp-servers"], {
		servers: [
			{
				id: "server-private",
				slug: "private-tools",
				name: "Private integration",
				url: privateUrl,
				transport: "streamable_http",
				auth_mode: "gateway_held",
				credential_kind: "bearer",
				credential_header: null,
				credential_last4: "abcd",
				enabled: true,
			},
		],
		limits: serverLimits,
	});
	client.setQueryData(["gateway-control", "mcp-policy"], policyView);
	mockFetch(() => json({ error: "forbidden" }, 403));
	// A role downgrade must not briefly reveal previously cached configuration.
	render(
		<QueryClientProvider client={client}>
			<RoleProvider {...{ role: "viewer" as const }}>
				<McpControls />
			</RoleProvider>
		</QueryClientProvider>,
	);
	expect(screen.queryByText(privateUrl)).toBeNull();
	expect(screen.queryByText(/Private integration/)).toBeNull();
	expect(
		screen.queryByRole("button", {
			name: /Add server|Save tool policy|Edit Private|Test Private|Archive Private/,
		}),
	).toBeNull();
	await screen.findAllByRole("alert");
	expect(document.body.textContent).not.toContain(privateUrl);
});

for (const [name, Panel] of [
	["data_controls", DataControls],
	["mcp_controls", McpControls],
	["approvals", Approvals],
] as const) {
	it(`${name}_loading_does_not_claim_empty_data`, () => {
		mockFetch(() => new Promise<Response>(() => {}));
		mount(<Panel />);
		expect(screen.getAllByLabelText("Loading").length).toBeGreaterThan(0);
		expect(
			screen.queryByText(
				/No active keys|No servers connected|No pending requests/,
			),
		).toBeNull();
		expect(
			screen.queryByRole("button", {
				name: /Save retention|Add server|Approve send_email/,
			}),
		).toBeNull();
	});
}

it("data_controls_empty_keys_explains_how_to_add_an_override", async () => {
	mockFetch(
		when("GET", "/data-controls", () => json({ ...dataView, keys: [] })),
		captureRead(),
	);
	mount(<DataControls />);
	await screen.findByText(/No active keys.*Create a key/);
	expect(screen.queryByRole("button", { name: "Save key capture" })).toBeNull();
});

it("mcp_empty_servers_explains_setup_and_offers_a_real_control", async () => {
	mockFetch(...mcpReads());
	mount(<McpControls />);
	await screen.findByText(
		"No servers connected. Add an upstream server to begin.",
	);
	fireEvent.click(screen.getByRole("button", { name: "Add server" }));
	expect(screen.getByLabelText("Server name")).toBeTruthy();
	expect(screen.getByLabelText(/^Endpoint slug/)).toBeTruthy();
});

for (const [name, Panel, path] of [
	["data_controls", DataControls, "/data-controls"],
	["approvals", Approvals, "/approvals"],
] as const) {
	for (const status of [403, 503]) {
		it(`${name}_read_${status}_shows_refusal_without_fabricating_empty_state`, async () => {
			mockFetch(
				when("GET", path, () =>
					json({ error: status === 403 ? "forbidden" : "unavailable" }, status),
				),
				...approvalSettings(),
			);
			mount(<Panel />);
			await screen.findAllByRole("alert");
			expect(document.body.textContent).toContain(`HTTP ${status}`);
			expect(
				screen.queryByText(/No active keys|No pending requests/),
			).toBeNull();
			expect(
				screen.queryByRole("button", {
					name: /Save retention|Approve send_email/,
				}),
			).toBeNull();
			if (status === 503)
				expect(
					screen.getAllByRole("button", { name: "Retry" }).length,
				).toBeGreaterThan(0);
		});
	}
}

it("approval_viewer_receives_refusal_and_no_decision_or_settings_controls", async () => {
	const { calls } = mockFetch(
		when("GET", "/approvals", () => json({ error: "forbidden" }, 403)),
	);
	mount(<Approvals />, "viewer");
	await screen.findAllByRole("alert");
	expect(
		screen.queryByRole("button", {
			name: /Approve |Deny |Save approval settings|Add model approval rule/,
		}),
	).toBeNull();
	expect(calls.every((c) => c.method === "GET")).toBe(true);
	expect(calls.some((c) => c.url.includes("approvals/settings"))).toBe(false);
});

it("data_controls_retention_conflict_preserves_confirmation_without_success", async () => {
	mockFetch(
		when("GET", "/data-controls", () => json(dataView)),
		captureRead(),
		when("PUT", "/data-controls/retention", () =>
			json(
				{
					error: "retention_conflict",
					message: "Retention changed. Refresh and review the new window.",
				},
				409,
			),
		),
	);
	mount(<DataControls />);
	fireEvent.change(await screen.findByLabelText("Retention (days)"), {
		target: { value: "90" },
	});
	fireEvent.change(screen.getByLabelText("Confirm deletion"), {
		target: { value: "delete data older than 90 days" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
	await screen.findByRole("alert");
	expect(
		(screen.getByLabelText("Retention (days)") as HTMLInputElement).value,
	).toBe("90");
	expect(
		(screen.getByLabelText("Confirm deletion") as HTMLInputElement).value,
	).toBe("delete data older than 90 days");
	expect(screen.queryByText(/Retention saved/)).toBeNull();
});

it("mcp_policy_conflict_preserves_edit_without_claiming_success", async () => {
	mockFetch(
		...mcpReads(),
		when("PUT", "/mcp-policy", () =>
			json(
				{
					error: "policy_conflict",
					message: "Policy changed. Refresh before saving.",
				},
				409,
			),
		),
	);
	mount(<McpControls />);
	fireEvent.change(await screen.findByLabelText("Tool rules"), {
		target: { value: "enforce" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save tool policy" }));
	await screen.findByRole("alert");
	expect((screen.getByLabelText("Tool rules") as HTMLSelectElement).value).toBe(
		"enforce",
	);
	expect(screen.queryByText("Policy saved")).toBeNull();
});

it("approval_decision_conflict_refetches_status_and_removes_stale_actions", async () => {
	let decided = false;
	const { calls } = mockFetch(
		when("GET", "/approvals", () =>
			json({
				approvals: [{ ...approval, status: decided ? "approved" : "pending" }],
				pending: decided ? 0 : 1,
				next_cursor: null,
			}),
		),
		...approvalSettings(),
		when("POST", `/approvals/${approval.id}/approve`, () => {
			decided = true;
			return json(
				{
					error: "approval_not_pending",
					message: "This request is no longer pending.",
				},
				409,
			);
		}),
	);
	mount(<Approvals />);
	fireEvent.click(
		await screen.findByRole("button", { name: "Approve send_email" }),
	);
	await screen.findByText(/Requested by Assistant · approved/);
	expect(
		screen.queryByRole("button", { name: "Approve send_email" }),
	).toBeNull();
	expect(screen.queryByRole("button", { name: "Deny send_email" })).toBeNull();
	expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
	expect(document.body.textContent).not.toContain(approval.id);
	expect(document.body.textContent).not.toContain(approval.requester_sub);
});

it("approval_decision_failure_preserves_note_and_pending_actions", async () => {
	mockFetch(
		when("GET", "/approvals", () =>
			json({ approvals: [approval], pending: 1, next_cursor: null }),
		),
		...approvalSettings(),
		when("POST", `/approvals/${approval.id}/approve`, () =>
			json(
				{
					error: "approval_unavailable",
					message: "The approval could not be saved.",
				},
				503,
			),
		),
	);
	mount(<Approvals />);
	fireEvent.change(
		await screen.findByLabelText("Decision note for send_email"),
		{ target: { value: "Reviewed recipient" } },
	);
	fireEvent.click(screen.getByRole("button", { name: "Approve send_email" }));
	await screen.findByRole("alert");
	expect(
		(screen.getByLabelText("Decision note for send_email") as HTMLInputElement)
			.value,
	).toBe("Reviewed recipient");
	expect(
		screen.getByRole("button", { name: "Approve send_email" }),
	).toBeTruthy();
	expect(document.body.textContent).toContain(
		"Requested by Assistant · pending",
	);
});
