// @vitest-environment jsdom
// Founder 2026-11-19: an owner can publish a protected-tool policy file from the dashboard
// (previously API-only), and sees the active policies with their versions and hashes.
import {
	cleanup,
	fireEvent,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
	ProtectedPolicies,
	parseDocument,
	templateFor,
} from "./ProtectedPolicies";
import { json, mockFetch, mount, openDialog, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const active = {
	tool_ref: "11111111-1111-4111-8111-111111111111",
	server_id: "22222222-2222-4222-8222-222222222222",
	tool_name: "payments.transfer",
	contract_version: 1,
	policy_id: "33333333-3333-4333-8333-333333333333",
	policy_version: 2,
	policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaa",
	contract_hash: "sha256:bbbbbbbbbbbbbbbbbbbb",
	publisher_sub: "user_01",
};
// A duplicated key and a >2^53 integer: a parse-then-stringify would change both, so the
// body must be the exact text (security review M1).
const doc =
	'{"contract":{"tool_name":"payments.transfer","n":9007199254740993},"policy":{"policy_id":"p1","version":3,"version":4}}';

function type(text: string) {
	fireEvent.change(screen.getByLabelText("Policy document"), {
		target: { value: text },
	});
}

it("lists_active_policies_with_version_and_hashes", async () => {
	mockFetch(when("GET", "action-policies", () => json({ policies: [active] })));
	mount(<ProtectedPolicies />);
	expect(await screen.findByText("payments.transfer")).toBeTruthy();
	expect(screen.getByText("v2")).toBeTruthy();
	expect(screen.getByTitle(active.policy_hash)).toBeTruthy();
});

it("empty_state_offers_the_publish_action", async () => {
	mockFetch(when("GET", "action-policies", () => json({ policies: [] })));
	mount(<ProtectedPolicies />);
	expect(
		await screen.findByText(/No protected-tool policies are active/),
	).toBeTruthy();
	expect(screen.getByRole("button", { name: "Publish policy" })).toBeTruthy();
});

it("publishes_the_document_after_confirmation_and_shows_the_result", async () => {
	const { calls } = mockFetch(
		when("GET", "action-policies", () => json({ policies: [] })),
		when("POST", "action-policies", () =>
			json(
				{
					tool_ref: active.tool_ref,
					policy_id: active.policy_id,
					policy_version: 3,
					policy_hash: "sha256:cccc",
					contract_hash: "sha256:dddd",
					warnings: ["principal_issuer_missing"],
				},
				201,
			),
		),
	);
	mount(<ProtectedPolicies />);
	await screen.findByText(/No protected-tool policies/);
	type(doc);
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	expect(
		within(openDialog()).getByText(
			/tool payments\.transfer · policy p1 · version 4/,
		),
	).toBeTruthy();
	fireEvent.click(
		within(openDialog()).getByRole("button", { name: "Publish" }),
	);
	expect(await screen.findByText("Published policy version 3.")).toBeTruthy();
	expect(screen.getByText(/no identity issuer is registered/)).toBeTruthy();
	const raw = vi
		.mocked(fetch)
		.mock.calls.find(([, init]) => init?.method === "POST")?.[1]?.body;
	expect(raw).toBe(doc);
	expect(calls.some((c) => c.method === "POST")).toBe(true);
});

it("names_the_refusal_in_plain_words", async () => {
	mockFetch(
		when("GET", "action-policies", () => json({ policies: [] })),
		when("POST", "action-policies", () =>
			json({ error: "policy_version_must_increase" }, 409),
		),
	);
	mount(<ProtectedPolicies />);
	await screen.findByText(/No protected-tool policies/);
	type(doc);
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	fireEvent.click(
		within(openDialog()).getByRole("button", { name: "Publish" }),
	);
	expect(
		await screen.findByText(/Raise the version and publish again/),
	).toBeTruthy();
});

it("invalid_json_never_reaches_the_gateway", async () => {
	const { calls } = mockFetch(
		when("GET", "action-policies", () => json({ policies: [] })),
	);
	mount(<ProtectedPolicies />);
	await screen.findByText(/No protected-tool policies/);
	type("{ not json");
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	expect(screen.getByText("The file is not valid JSON.")).toBeTruthy();
	await waitFor(() =>
		expect(calls.some((c) => c.method === "POST")).toBe(false),
	);
});

it("a_developer_cannot_publish", async () => {
	mockFetch(when("GET", "action-policies", () => json({ policies: [] })));
	mount(<ProtectedPolicies />, "developer");
	await screen.findByText(/No protected-tool policies/);
	type(doc);
	expect(
		(
			screen.getByRole("button", {
				name: "Publish policy",
			}) as HTMLButtonElement
		).disabled,
	).toBe(true);
	expect(screen.getByTestId("why-disabled")).toBeTruthy();
});

it("parse_document_requires_contract_and_policy", () => {
	expect(parseDocument("[]")).toMatch(/JSON object/);
	expect(parseDocument('{"policy":{}}')).toBe("The file has no contract.");
	expect(parseDocument('{"contract":{}}')).toBe("The file has no policy.");
	expect(typeof parseDocument('{"contract":{},"policy":{}}')).toBe("object");
});

it("a_discovered_tool_fills_a_valid_starting_file", async () => {
	mockFetch(
		when("GET", "action-policies", () => json({ policies: [] })),
		when("GET", "mcp-tools", () =>
			json({
				tools: [
					{
						server_id: "44444444-4444-4444-8444-444444444444",
						server_name: "payments",
						tool_name: "transfer",
					},
				],
			}),
		),
		when("GET", "approvals/settings", () =>
			json({
				settings: { require_second_approver: false, default_ttl_secs: 1200 },
			}),
		),
	);
	mount(<ProtectedPolicies />);
	const pick = await screen.findByLabelText("Start from a discovered tool");
	fireEvent.change(pick, {
		target: { value: "44444444-4444-4444-8444-444444444444/transfer" },
	});
	const text = (screen.getByLabelText("Policy document") as HTMLTextAreaElement)
		.value;
	const parsed = parseDocument(text);
	expect(typeof parsed).toBe("object");
	const d = parsed as {
		contract: { server_id: string; tool_name: string; protected: boolean };
		policy: { approval_ttl_secs: number; rules: { decision: string }[] };
	};
	expect(d.contract.server_id).toBe("44444444-4444-4444-8444-444444444444");
	expect(d.contract.tool_name).toBe("transfer");
	expect(d.contract.protected).toBe(true);
	expect(d.policy.approval_ttl_secs).toBe(1200);
	expect(d.policy.rules[0]?.decision).toBe("require_approval");
});

it("no_template_picker_without_discovered_tools", async () => {
	mockFetch(
		when("GET", "action-policies", () => json({ policies: [] })),
		when("GET", "mcp-tools", () => json({ tools: [] })),
		when("GET", "approvals/settings", () =>
			json({
				settings: { require_second_approver: false, default_ttl_secs: 900 },
			}),
		),
	);
	mount(<ProtectedPolicies />);
	await screen.findByText(/No protected-tool policies/);
	expect(screen.queryByLabelText("Start from a discovered tool")).toBeNull();
});

it("an_already_protected_tool_keeps_its_identity_and_bumps_the_version", () => {
	const text = templateFor(
		{
			server_id: active.server_id,
			server_name: "payments",
			tool_name: active.tool_name,
		},
		900,
		active,
	);
	const d = JSON.parse(text);
	expect(d.contract.tool_ref).toBe(active.tool_ref);
	expect(d.contract.version).toBe(active.contract_version);
	expect(d.policy.policy_id).toBe(active.policy_id);
	expect(d.policy.version).toBe(active.policy_version + 1);
});
