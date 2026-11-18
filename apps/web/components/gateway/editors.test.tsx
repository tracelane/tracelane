// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	GuardrailPolicyEditor,
	customListError,
	parseTermLines,
	termListError,
} from "./GuardrailPolicyEditor";
import { RoutingEditor } from "./RoutingEditor";
import { json, mockFetch, mount, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

// Shapes copied from routing::routes::get_routing and guardrail::policy_api::read.
const limits = {
	max_virtual_models: 2,
	max_targets_per_model: 2,
	max_pool_keys_per_provider: 2,
	max_attempts: 4,
	doc_max_bytes: 8192,
	rules: {
		max_rules: 2,
		max_arms: 3,
		max_match_value_bytes: 128,
		sticky_key_max_bytes: 128,
		match_header_denylist: ["authorization", "cookie"],
	},
	breaker: {
		consecutive_failures_min: 1,
		consecutive_failures_max: 10,
		cooldown_secs_min: 1,
		cooldown_secs_max: 300,
	},
	timeouts: { min_ms: 1, total_min_ms: 1, max_ms: 1000, max_rules: 2 },
};
const baseDoc = {
	virtual_models: {
		"my-chat": {
			strategy: "priority",
			targets: [{ model: "gpt-4o" }],
		},
	},
	key_pools: [
		{ provider: "openai", strategy: "priority", keys: [{ label: "primary" }] },
	],
	rules: [],
	breaker: { consecutive_failures: 3, cooldown_secs: 30 },
};
const routing = (doc: Record<string, unknown> = baseDoc, can_edit = true) => ({
	doc,
	version: 7,
	valid: true,
	limits,
	can_edit,
});
const guardrails = (
	policy: unknown = {
		rails: {
			R1_cost: {
				enabled: true,
				mode: "block",
				thresholds: { max_input_tokens: 1000 },
			},
		},
	},
) => ({
	scope: "workspace",
	id: "00000000-0000-0000-0000-000000000001",
	policy,
	etag: `"${"a".repeat(64)}"`,
	can_edit: true,
	effective: {
		R1_cost: {
			entitled: true,
			enabled: true,
			override: {
				enabled: true,
				mode: "block",
				thresholds: { max_input_tokens: 1000 },
			},
			default_behavior: {
				mode: "block",
				thresholds: { max_input_tokens: 1000 },
			},
		},
		R2_secrets_pii: {
			entitled: false,
			enabled: false,
			override: null,
			default_behavior: { mode: "redact" },
		},
		R8_injection: {
			entitled: true,
			enabled: true,
			override: null,
			default_behavior: { mode: "built_in", high_confidence: "block" },
		},
	},
});

describe("routing editor", () => {
	it("routing_empty shows an add action and no raw JSON", async () => {
		mockFetch(when("GET", "/routing", () => json(routing({}))));
		mount(<RoutingEditor />);
		expect(
			await screen.findByRole("button", { name: /Add virtual model/i }),
		).toBeTruthy();
		expect(screen.queryByTestId("slot-json")).toBeNull();
	});
	it("routing_invalid_stored_document shows a recoverable error instead of a broken form", async () => {
		mockFetch(
			when("GET", "/routing", () =>
				json({
					...routing({
						virtual_models: { broken: { targets: "not an array" } },
					}),
					valid: false,
				}),
			),
		);
		mount(<RoutingEditor />);
		expect(await screen.findByText(/cannot be opened safely/i)).toBeTruthy();
		expect(screen.queryByRole("button", { name: /Save routing/i })).toBeNull();
	});
	it("routing_model renders a named model and its concrete target", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		expect(await screen.findByDisplayValue("my-chat")).toBeTruthy();
		expect(screen.getByDisplayValue("gpt-4o")).toBeTruthy();
	});
	it("routing_strategy saves exactly one full document with the GET version", async () => {
		const calls: { method: string; body: unknown; ifMatch: string | null }[] =
			[];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_url: string, init?: RequestInit) => {
				if (init?.method === "PUT") {
					const headers = new Headers(init.headers);
					calls.push({
						method: "PUT",
						body: JSON.parse(String(init.body)),
						ifMatch: headers.get("if-match"),
					});
					return json({ doc: baseDoc, version: 8 });
				}
				return json(routing());
			}),
		);
		mount(<RoutingEditor />);
		fireEvent.change(await screen.findByLabelText(/Strategy for my-chat/i), {
			target: { value: "weighted" },
		});
		expect(screen.getByText(/1 pending change/i)).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		await waitFor(() => expect(calls).toHaveLength(1));
		expect(calls[0]).toEqual({
			method: "PUT",
			ifMatch: "7",
			body: {
				doc: {
					...baseDoc,
					virtual_models: {
						"my-chat": { strategy: "weighted", targets: [{ model: "gpt-4o" }] },
					},
				},
			},
		});
	});
	it("routing_target adds a target and preserves pools", async () => {
		const { calls } = mockFetch(
			when("GET", "/routing", () => json(routing())),
			when("PUT", "/routing", () => json({ doc: baseDoc, version: 8 })),
		);
		mount(<RoutingEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Add target to my-chat/i }),
		);
		fireEvent.change(screen.getByLabelText(/Target 2 model/i), {
			target: { value: "claude-3-7-sonnet" },
		});
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(
			(calls.find((c) => c.method === "PUT")?.body as { doc: typeof baseDoc })
				.doc.key_pools,
		).toEqual(baseDoc.key_pools);
	});
	it("routing_order moves targets without inventing a priority field", async () => {
		const doc = {
			...baseDoc,
			virtual_models: {
				"my-chat": {
					strategy: "priority",
					targets: [{ model: "gpt-4o" }, { model: "claude-3-7-sonnet" }],
				},
			},
		};
		const { calls } = mockFetch(
			when("GET", "/routing", () => json(routing(doc))),
			when("PUT", "/routing", () => json({ doc, version: 8 })),
		);
		mount(<RoutingEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Move target 2 up/i }),
		);
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(
			(
				calls.find((c) => c.method === "PUT")?.body as { doc: typeof doc }
			).doc.virtual_models["my-chat"].targets.map((t) => t.model),
		).toEqual(["claude-3-7-sonnet", "gpt-4o"]);
	});
	it("routing_pool permits a second key label within its cap", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Add key to openai/i }),
		);
		expect(screen.getByLabelText(/Key 2 label/i)).toBeTruthy();
	});
	it("routing_breaker shows bounded numeric fields", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		expect(
			(
				(await screen.findByLabelText(
					/Consecutive failures/i,
				)) as HTMLInputElement
			).max,
		).toBe("10");
		expect(
			(screen.getByLabelText(/Cooldown seconds/i) as HTMLInputElement).max,
		).toBe("300");
	});
	it("routing_header offers a header predicate", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		fireEvent.click(await screen.findByRole("button", { name: /Add rule/i }));
		fireEvent.change(screen.getByLabelText(/Match source/i), {
			target: { value: "header" },
		});
		expect(screen.getByLabelText(/Header name/i)).toBeTruthy();
	});
	it("routing_split shows split arms and sticky source", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		fireEvent.click(await screen.findByRole("button", { name: /Add rule/i }));
		fireEvent.change(screen.getByLabelText(/Action/i), {
			target: { value: "split" },
		});
		expect(screen.getByLabelText(/Sticky source/i)).toBeTruthy();
		expect(screen.getByLabelText(/Arm 1 percent/i)).toBeTruthy();
	});
	it("routing_unchanged disables save", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		expect(
			(
				(await screen.findByRole("button", {
					name: /Save routing/i,
				})) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("routing_viewer shows the read refusal without write controls", async () => {
		const { calls } = mockFetch(
			when("GET", "/routing", () => json({ error: "forbidden" }, 403)),
		);
		mount(<RoutingEditor />, "viewer");
		expect(
			await screen.findByText(
				"Only workspace admins can view and change routing.",
			),
		).toBeTruthy();
		expect(screen.queryByRole("button", { name: /Save routing/i })).toBeNull();
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});
	it("routing_conflict leaves the edit and shows the 409", async () => {
		mockFetch(
			when("GET", "/routing", () => json(routing())),
			when("PUT", "/routing", () =>
				json(
					{
						error: "version_conflict",
						message: "the routing document changed since you read it",
					},
					409,
				),
			),
		);
		mount(<RoutingEditor />);
		fireEvent.change(await screen.findByLabelText(/Strategy for my-chat/i), {
			target: { value: "weighted" },
		});
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		expect((await screen.findByRole("alert")).textContent).toMatch(
			/changed since you read it/i,
		);
		expect(
			(screen.getByLabelText(/Strategy for my-chat/i) as HTMLSelectElement)
				.value,
		).toBe("weighted");
		expect(
			(
				screen.getByRole("button", {
					name: /Save routing/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
		expect(
			screen.getByRole("button", { name: /Reload latest routing/i }),
		).toBeTruthy();
	});
	it("routing_reload uses the new version before a second save", async () => {
		let reads = 0;
		const versions: string[] = [];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_url: string, init?: RequestInit) => {
				if (init?.method === "PUT") {
					versions.push(new Headers(init.headers).get("if-match") ?? "");
					return versions.length === 1
						? json({ error: "version_conflict", message: "changed" }, 409)
						: json({ doc: baseDoc, version: 9 });
				}
				reads += 1;
				return json({ ...routing(), version: reads === 1 ? 7 : 8 });
			}),
		);
		mount(<RoutingEditor />);
		fireEvent.change(await screen.findByLabelText(/Strategy for my-chat/i), {
			target: { value: "weighted" },
		});
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		fireEvent.click(
			await screen.findByRole("button", { name: /Reload latest routing/i }),
		);
		await waitFor(() =>
			expect(
				(screen.getByLabelText(/Strategy for my-chat/i) as HTMLSelectElement)
					.value,
			).toBe("priority"),
		);
		fireEvent.change(screen.getByLabelText(/Strategy for my-chat/i), {
			target: { value: "cost" },
		});
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		await waitFor(() => expect(versions).toEqual(["7", "8"]));
	});
	it("routing_refetch preserves a draft and blocks a stale save", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		const { client } = mount(<RoutingEditor />);
		fireEvent.change(await screen.findByLabelText(/Strategy for my-chat/i), {
			target: { value: "weighted" },
		});
		client.setQueryData(["gateway-control", "routing"], {
			...routing(),
			version: 8,
		});
		await waitFor(() =>
			expect(
				screen.getByText(/Routing changed while you were editing/i),
			).toBeTruthy(),
		);
		expect(
			(screen.getByLabelText(/Strategy for my-chat/i) as HTMLSelectElement)
				.value,
		).toBe("weighted");
		expect(
			(
				screen.getByRole("button", {
					name: /Save routing/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("routing_multiple_sticky_sources cannot be silently replaced", async () => {
		const doc = {
			...baseDoc,
			rules: [
				{
					id: "canary",
					wires: ["chat"],
					match: { model: "my-chat" },
					action: {
						split: {
							sticky_by: ["end_user", "session"],
							on_missing_identity: "stable",
							arms: [
								{ name: "a", route_to: "gpt-4o", bp: 5000 },
								{ name: "b", route_to: "gpt-4o" },
							],
						},
					},
				},
			],
		};
		const { calls } = mockFetch(
			when("GET", "/routing", () => json(routing(doc))),
			when("PUT", "/routing", () => json({ doc, version: 8 })),
		);
		mount(<RoutingEditor />);
		expect(
			((await screen.findByLabelText(/Sticky source/i)) as HTMLSelectElement)
				.disabled,
		).toBe(true);
		fireEvent.change(screen.getByLabelText(/Arm 1 percent/i), {
			target: { value: "40" },
		});
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(
			(calls.find((c) => c.method === "PUT")?.body as { doc: typeof doc }).doc
				.rules[0]?.action.split.sticky_by,
		).toEqual(["end_user", "session"]);
	});
	it("routing_field places a server 422 on its field", async () => {
		mockFetch(
			when("GET", "/routing", () => json(routing())),
			when("PUT", "/routing", () =>
				json(
					{
						error: "invalid_field",
						field: "breaker.cooldown_secs",
						message: "too long",
					},
					422,
				),
			),
		);
		mount(<RoutingEditor />);
		fireEvent.change(await screen.findByLabelText(/Cooldown seconds/i), {
			target: { value: "31" },
		});
		fireEvent.click(screen.getByRole("button", { name: /Save routing/i }));
		expect(await screen.findByText("too long")).toBeTruthy();
	});
	it("routing_denied_header blocks save before a PUT", async () => {
		const { calls } = mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		fireEvent.click(await screen.findByRole("button", { name: /Add rule/i }));
		fireEvent.change(screen.getByLabelText(/Match source/i), {
			target: { value: "header" },
		});
		fireEvent.change(screen.getByLabelText(/Header name/i), {
			target: { value: "Authorization" },
		});
		expect(
			(
				screen.getByRole("button", {
					name: /Save routing/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});
	it("routing_target_cap disables adding beyond the limit", async () => {
		const doc = {
			...baseDoc,
			virtual_models: {
				"my-chat": {
					strategy: "priority",
					targets: [{ model: "gpt-4o" }, { model: "claude-3-7-sonnet" }],
				},
			},
		};
		mockFetch(when("GET", "/routing", () => json(routing(doc))));
		mount(<RoutingEditor />);
		expect(
			(
				(await screen.findByRole("button", {
					name: /Add target to my-chat/i,
				})) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("routing_model_cap disables add at the limit", async () => {
		const doc = {
			...baseDoc,
			virtual_models: {
				...baseDoc.virtual_models,
				other: { strategy: "priority", targets: [{ model: "gpt-4o" }] },
			},
		};
		mockFetch(when("GET", "/routing", () => json(routing(doc))));
		mount(<RoutingEditor />);
		expect(
			(
				(await screen.findByRole("button", {
					name: /Add virtual model/i,
				})) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("routing_add_model never overwrites an existing generated name", async () => {
		const doc = {
			virtual_models: {
				"new-model-2": { strategy: "cost", targets: [{ model: "gpt-4o" }] },
			},
		};
		mockFetch(when("GET", "/routing", () => json(routing(doc))));
		mount(<RoutingEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Add virtual model/i }),
		);
		expect(screen.getByLabelText("Virtual model new-model-2")).toBeTruthy();
		expect(
			(screen.getByLabelText(/Strategy for new-model-2/i) as HTMLSelectElement)
				.value,
		).toBe("cost");
		expect(screen.getByDisplayValue("gpt-4o")).toBeTruthy();
	});
	it("routing_arm_cap disables another split arm", async () => {
		const doc = {
			...baseDoc,
			rules: [
				{
					id: "canary",
					wires: ["chat"],
					match: { model: "my-chat" },
					action: {
						split: {
							sticky_by: ["end_user"],
							on_missing_identity: "stable",
							arms: [
								{ name: "a", route_to: "gpt-4o", bp: 5000 },
								{ name: "b", route_to: "gpt-4o", bp: 3000 },
								{ name: "c", route_to: "gpt-4o" },
							],
						},
					},
					salt: "salt",
				},
			],
		};
		mockFetch(when("GET", "/routing", () => json(routing(doc))));
		mount(<RoutingEditor />);
		expect(
			(
				(await screen.findByRole("button", {
					name: /Add split arm/i,
				})) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("routing_breaker_bound refuses an out-of-range value", async () => {
		mockFetch(when("GET", "/routing", () => json(routing())));
		mount(<RoutingEditor />);
		fireEvent.change(await screen.findByLabelText(/Cooldown seconds/i), {
			target: { value: "301" },
		});
		expect(
			(
				screen.getByRole("button", {
					name: /Save routing/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("routing_hidden never submits a scrubbed value", async () => {
		const { calls } = mockFetch(
			when("GET", "/routing", () =>
				json(routing({ ...baseDoc, secret: "[hidden]" })),
			),
		);
		mount(<RoutingEditor />);
		expect(await screen.findByText(/cannot be edited safely/i)).toBeTruthy();
		expect(
			(
				screen.getByRole("button", {
					name: /Save routing/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});
	it("routing_existing_predicates keeps a prefix and metadata list editable", async () => {
		const doc = {
			...baseDoc,
			rules: [
				{
					id: "region",
					wires: ["chat"],
					match: {
						model: "my-chat",
						header: { name: "x-region", prefix: "eu" },
						metadata: { key: "group", in: ["one", "two"] },
					},
					action: { route_to: "gpt-4o" },
					salt: "salt",
				},
			],
		};
		mockFetch(when("GET", "/routing", () => json(routing(doc))));
		mount(<RoutingEditor />);
		expect(
			((await screen.findByLabelText(/Header prefix/i)) as HTMLInputElement)
				.value,
		).toBe("eu");
		expect(
			(screen.getByLabelText(/Metadata values/i) as HTMLInputElement).value,
		).toBe("one, two");
	});
});

describe("guardrail policy editor", () => {
	it("guardrail_empty shows built-in rails when no workspace override exists", async () => {
		mockFetch(when("GET", "/guardrails/policy", () => json(guardrails(null))));
		mount(<GuardrailPolicyEditor />);
		expect(
			await screen.findByRole("heading", { name: "Cost limits" }),
		).toBeTruthy();
		expect(screen.getAllByText("Built-in behavior").length).toBeGreaterThan(0);
		expect(
			(
				screen.getByRole("button", {
					name: /Save guardrail policy/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("guardrail_invalid_stored_policy shows a recoverable error", async () => {
		mockFetch(
			when("GET", "/guardrails/policy", () =>
				json(guardrails({ broken: true })),
			),
		);
		mount(<GuardrailPolicyEditor />);
		expect(await screen.findByText(/cannot be opened safely/i)).toBeTruthy();
		expect(
			screen.queryByRole("button", { name: /Save guardrail policy/i }),
		).toBeNull();
	});
	it("guardrail_rows renders named rows and locks unentitled rails", async () => {
		mockFetch(when("GET", "/guardrails/policy", () => json(guardrails())));
		mount(<GuardrailPolicyEditor />);
		expect(
			await screen.findByRole("heading", { name: "Cost limits" }),
		).toBeTruthy();
		expect(
			screen.getByRole("heading", { name: "Secrets and personal data" }),
		).toBeTruthy();
		expect(screen.getByText(/Plan needed/i)).toBeTruthy();
		expect(screen.queryByTestId("slot-json")).toBeNull();
	});
	it("guardrail_save changes an entitled rail and sends exact full policy", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(guardrails())),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.change(await screen.findByLabelText(/Cost limits mode/i), {
			target: { value: "observe" },
		});
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
			rails: {
				R1_cost: {
					enabled: true,
					mode: "observe",
					thresholds: { max_input_tokens: 1000 },
				},
			},
		});
	});
	it("guardrail_reset removes only that rail override", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(guardrails())),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Reset Cost limits/i }),
		);
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ rails: {} });
	});
	it("guardrail_viewer shows the read refusal without write controls", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () =>
				json({ error: "forbidden" }, 403),
			),
		);
		mount(<GuardrailPolicyEditor />, "viewer");
		expect(
			await screen.findByText(
				"Only workspace admins can view and change guardrail policy.",
			),
		).toBeTruthy();
		expect(
			screen.queryByRole("button", { name: /Save guardrail policy/i }),
		).toBeNull();
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});
	it("guardrail_missing_route explains that this gateway does not serve it", async () => {
		mockFetch(when("GET", "/guardrails/policy", () => json({}, 404)));
		mount(<GuardrailPolicyEditor />);
		expect(
			await screen.findByText(
				/gateway does not serve the guardrail policy route/i,
			),
		).toBeTruthy();
	});
	it("guardrail_invalid keeps edits when the server rejects a policy", async () => {
		mockFetch(
			when("GET", "/guardrails/policy", () => json(guardrails())),
			when("PUT", "/guardrails/policy", () =>
				json({ error: "invalid_policy" }, 400),
			),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.change(await screen.findByLabelText(/Cost limits mode/i), {
			target: { value: "observe" },
		});
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		expect(await screen.findByRole("alert")).toBeTruthy();
		expect(
			(screen.getByLabelText(/Cost limits mode/i) as HTMLSelectElement).value,
		).toBe("observe");
	});
	it("guardrail_hidden never round-trips a scrubbed policy", async () => {
		const view = guardrails({
			rails: {
				R1_cost: {
					enabled: true,
					mode: "block",
					thresholds: { max_input_tokens: 1000 },
				},
				R2_secrets_pii: { enabled: true, mode: "redact", pii: "[hidden]" },
			},
		});
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(view)),
		);
		mount(<GuardrailPolicyEditor />);
		expect(await screen.findByText(/cannot be edited safely/i)).toBeTruthy();
		expect(
			(
				screen.getByRole("button", {
					name: /Save guardrail policy/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});
	it("guardrail_threshold keeps the built-in block mode when adding an override", async () => {
		const view = guardrails({ rails: {} });
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(view)),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.change(
			await screen.findByLabelText(/Cost limits Maximum input tokens/i),
			{ target: { value: "700" } },
		);
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
			rails: {
				R1_cost: {
					enabled: true,
					mode: "block",
					thresholds: { max_input_tokens: 700 },
				},
			},
		});
	});
	it("guardrail_builtin_requires_explicit_mode before changing a score", async () => {
		const view = guardrails({ rails: {} });
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(view)),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		const score = (await screen.findByLabelText(
			/Prompt injection Minimum score/i,
		)) as HTMLInputElement;
		expect(score.disabled).toBe(true);
		fireEvent.change(screen.getByLabelText(/Prompt injection mode/i), {
			target: { value: "block" },
		});
		fireEvent.change(score, { target: { value: "0.8" } });
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(
			(
				calls.find((c) => c.method === "PUT")?.body as {
					rails: { R8_injection: { mode: string } };
				}
			).rails.R8_injection.mode,
		).toBe("block");
	});
	it("guardrail_existing_override_without_mode shows the gateway's observe default", async () => {
		const view = guardrails({ rails: { R8_injection: { enabled: true } } });
		mockFetch(when("GET", "/guardrails/policy", () => json(view)));
		mount(<GuardrailPolicyEditor />);
		expect(
			(
				(await screen.findByLabelText(
					/Prompt injection mode/i,
				)) as HTMLSelectElement
			).value,
		).toBe("observe");
	});
	it("guardrail_refetch preserves a draft and blocks overwrite", async () => {
		mockFetch(when("GET", "/guardrails/policy", () => json(guardrails())));
		const { client } = mount(<GuardrailPolicyEditor />);
		fireEvent.change(
			await screen.findByLabelText(/Cost limits Maximum input tokens/i),
			{ target: { value: "700" } },
		);
		client.setQueryData(["gateway-control", "guardrails/policy"], {
			...guardrails({
				rails: {
					R1_cost: {
						enabled: true,
						mode: "block",
						thresholds: { max_input_tokens: 900 },
					},
				},
			}),
			etag: `"${"b".repeat(64)}"`,
		});
		await waitFor(() =>
			expect(
				screen.getByText(/policy changed while you were editing/i),
			).toBeTruthy(),
		);
		expect(
			(
				screen.getByLabelText(
					/Cost limits Maximum input tokens/i,
				) as HTMLInputElement
			).value,
		).toBe("700");
		expect(
			(
				screen.getByRole("button", {
					name: /Save guardrail policy/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
	it("guardrail_conflict sends the GET ETag and preserves a stale draft", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(guardrails())),
			when("PUT", "/guardrails/policy", () =>
				json({ error: "policy_conflict" }, 409),
			),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.change(
			await screen.findByLabelText(/Cost limits Maximum input tokens/i),
			{ target: { value: "700" } },
		);
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		expect(
			await screen.findByText(/conflicts with current state/i),
		).toBeTruthy();
		expect(calls.filter((c) => c.method === "GET")).toHaveLength(1);
		expect(calls.some((c) => c.method === "PUT")).toBe(true);
		expect(calls.find((c) => c.method === "PUT")?.ifMatch).toBe(
			`"${"a".repeat(64)}"`,
		);
		expect(
			(
				screen.getByLabelText(
					/Cost limits Maximum input tokens/i,
				) as HTMLInputElement
			).value,
		).toBe("700");
	});
});

const termLimits = { list_count: 3, term_bytes: 12 };
const r7View = (policy: unknown) => {
	const view = guardrails(policy) as ReturnType<typeof guardrails> & {
		effective: Record<string, unknown>;
	};
	view.effective.R7_topic_competitor = {
		entitled: true,
		enabled: true,
		override: null,
		default_behavior: {
			mode: "built_in",
			denied_topic: "block",
			competitor: "redact",
			configured_terms: false,
			term_limits: termLimits,
		},
	};
	return view;
};

describe("guardrail term lists", () => {
	it("terms_parse trims lines and drops blanks", () => {
		expect(parseTermLines("  Initech \n\n\tGlobex\n")).toEqual([
			"Initech",
			"Globex",
		]);
		expect(parseTermLines("")).toEqual([]);
	});
	it("terms_bounds accept the bound and refuse past it", () => {
		expect(termListError(["a", "b", "c"], termLimits)).toBeNull();
		expect(termListError(["a", "b", "c", "d"], termLimits)).toMatch(
			/at most 3/,
		);
		expect(termListError(["x".repeat(12)], termLimits)).toBeNull();
		expect(termListError(["x".repeat(13)], termLimits)).toMatch(/12 bytes/);
		expect(termListError(["éééééé"], termLimits)).toBeNull();
		expect(termListError(["ééééééé"], termLimits)).toMatch(/bytes/);
	});
	it("terms_refuse blanks, control characters and missing limits", () => {
		expect(termListError([" "], termLimits)).toMatch(/blank/);
		expect(termListError(["a\u0007b"], termLimits)).toMatch(/control/);
		expect(termListError(["a"], undefined)).toMatch(/did not report/);
		expect(termListError("a", termLimits)).toMatch(/not a list/);
		expect(termListError(undefined, termLimits)).toBeNull();
		expect(termListError(["..."], termLimits)).toMatch(/letter or digit/);
		expect(termListError(["C++", "機密"], termLimits)).toBeNull();
		expect(termListError(["a\uD800"], termLimits)).toMatch(/broken/);
		expect(termListError(["a😀"], termLimits)).toBeNull();
	});
	it("terms_need_mode keeps the lists disabled until a mode is chosen", async () => {
		mockFetch(when("GET", "/guardrails/policy", () => json(r7View(null))));
		mount(<GuardrailPolicyEditor />);
		const field = (await screen.findByLabelText(
			/Topic and competitor terms competitor names/i,
		)) as HTMLTextAreaElement;
		expect(field.disabled).toBe(true);
	});
	it("terms_save sends parsed lists under the observe mode", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(r7View(null))),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.change(
			await screen.findByLabelText(/Topic and competitor terms mode/i),
			{ target: { value: "observe" } },
		);
		fireEvent.change(
			screen.getByLabelText(/Topic and competitor terms competitor names/i),
			{ target: { value: "Initech\n\n Globex \n" } },
		);
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(
			(
				calls.find((c) => c.method === "PUT")?.body as {
					rails: Record<string, unknown>;
				}
			).rails.R7_topic_competitor,
		).toEqual({
			enabled: true,
			mode: "observe",
			terms: { competitors: ["Initech", "Globex"] },
		});
	});
	it("terms_over_limit blocks save before a PUT", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(r7View(null))),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.change(
			await screen.findByLabelText(/Topic and competitor terms mode/i),
			{ target: { value: "block" } },
		);
		fireEvent.change(
			screen.getByLabelText(/Topic and competitor terms denied topics/i),
			{ target: { value: "a\nb\nc\nd" } },
		);
		expect(await screen.findByRole("alert")).toBeTruthy();
		expect(screen.getByText(/at most 3 entries/)).toBeTruthy();
		const save = screen.getByRole("button", {
			name: /Save guardrail policy/i,
		}) as HTMLButtonElement;
		expect(save.disabled).toBe(true);
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});
	it("terms_stored lists load into the fields", async () => {
		mockFetch(
			when("GET", "/guardrails/policy", () =>
				json(
					r7View({
						rails: {
							R7_topic_competitor: {
								enabled: true,
								mode: "block",
								terms: { denied_topics: ["merger plans"] },
							},
						},
					}),
				),
			),
		);
		mount(<GuardrailPolicyEditor />);
		const field = (await screen.findByLabelText(
			/Topic and competitor terms denied topics/i,
		)) as HTMLTextAreaElement;
		expect(field.value).toBe("merger plans");
		expect(field.disabled).toBe(false);
	});
	it("terms_on_other_rail are refused", async () => {
		mockFetch(
			when("GET", "/guardrails/policy", () =>
				json(
					r7View({
						rails: {
							R1_cost: {
								enabled: true,
								mode: "block",
								terms: { competitors: ["x"] },
							},
						},
					}),
				),
			),
		);
		mount(<GuardrailPolicyEditor />);
		expect(
			await screen.findByText(/Term lists are only available for this rail/),
		).toBeTruthy();
	});
});

const customLimits = { custom_count: 2, custom_pattern_bytes: 16 };
const r2View = (policy: unknown) => {
	const view = guardrails(policy) as ReturnType<typeof guardrails> & {
		effective: Record<string, unknown>;
	};
	(view.effective as Record<string, unknown>).R2_secrets_pii = {
		entitled: true,
		enabled: true,
		override: null,
		default_behavior: { mode: "redact", custom_limits: customLimits },
	};
	return view;
};

describe("guardrail custom patterns", () => {
	it("custom_valid list passes and bounds refuse", () => {
		const ok = [
			{ name: "employee_id", pattern: "EMP-[0-9]{6}", action: "redact" },
		];
		expect(customListError(ok, customLimits)).toBeNull();
		expect(customListError(undefined, customLimits)).toBeNull();
		expect(
			customListError(
				[...ok, { ...ok[0], name: "b" }, { ...ok[0], name: "c" }],
				customLimits,
			),
		).toMatch(/At most 2/);
		expect(
			customListError([{ ...ok[0], pattern: "x".repeat(17) }], customLimits),
		).toMatch(/16 bytes/);
	});
	it("custom_refuses bad names, duplicates, empty patterns and missing limits", () => {
		const ok = { name: "e", pattern: "x", action: "redact" };
		for (const name of ["", "Upper", "a:b", "x".repeat(33)])
			expect(customListError([{ ...ok, name }], customLimits)).toMatch(
				/lowercase/,
			);
		expect(customListError([ok, ok], customLimits)).toMatch(/unique/);
		expect(customListError([{ ...ok, pattern: "" }], customLimits)).toMatch(
			/empty/,
		);
		expect(customListError([{ ...ok, action: "off" }], customLimits)).toMatch(
			/action/,
		);
		expect(customListError([ok], undefined)).toMatch(/did not report/);
	});
	it("custom_save sends a pattern under an observe default", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(r2View(null))),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Add custom pattern/i }),
		);
		fireEvent.change(
			screen.getByLabelText(/Secrets and personal data pattern 1 name/i),
			{ target: { value: "employee_id" } },
		);
		fireEvent.change(
			screen.getByLabelText(/Secrets and personal data pattern 1 expression/i),
			{ target: { value: "EMP-[0-9]{6}" } },
		);
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		const sent = (
			calls.find((c) => c.method === "PUT")?.body as {
				rails: { R2_secrets_pii: { pii: unknown } };
			}
		).rails.R2_secrets_pii.pii;
		expect(sent).toEqual({
			classes: {},
			custom: [
				{ name: "employee_id", pattern: "EMP-[0-9]{6}", action: "observe" },
			],
		});
	});
	it("custom_invalid name blocks save before a PUT", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () => json(r2View(null))),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Add custom pattern/i }),
		);
		fireEvent.change(
			screen.getByLabelText(/Secrets and personal data pattern 1 name/i),
			{ target: { value: "Bad Name" } },
		);
		expect(await screen.findByText(/lowercase letters/)).toBeTruthy();
		expect(
			(
				screen.getByRole("button", {
					name: /Save guardrail policy/i,
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
		expect(calls.some((c) => c.method === "PUT")).toBe(false);
	});
	it("custom_remove keeps existing classes and allowlist", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () =>
				json(
					r2View({
						rails: {
							R2_secrets_pii: {
								enabled: true,
								mode: "redact",
								pii: {
									classes: { email: "block" },
									allowlist: ["ok@example.com"],
									custom: [{ name: "e", pattern: "x", action: "redact" }],
								},
							},
						},
					}),
				),
			),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.click(
			await screen.findByRole("button", {
				name: /Remove Secrets and personal data pattern 1/i,
			}),
		);
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		expect(
			(
				calls.find((c) => c.method === "PUT")?.body as {
					rails: { R2_secrets_pii: { pii: unknown } };
				}
			).rails.R2_secrets_pii.pii,
		).toEqual({ classes: { email: "block" }, allowlist: ["ok@example.com"] });
	});
	it("custom_on_other_rail is refused", async () => {
		mockFetch(
			when("GET", "/guardrails/policy", () =>
				json(
					r2View({
						rails: {
							R1_cost: {
								enabled: true,
								mode: "block",
								pii: { classes: {}, custom: [] },
							},
						},
					}),
				),
			),
		);
		mount(<GuardrailPolicyEditor />);
		expect(
			await screen.findByText(
				/Custom patterns are only available for this rail/,
			),
		).toBeTruthy();
	});
});

describe("guardrail custom patterns keep the rail mode", () => {
	it("custom_first_pattern under Block seeds every built-in class as block", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/policy", () =>
				json(
					r2View({
						rails: { R2_secrets_pii: { enabled: true, mode: "block" } },
					}),
				),
			),
			when("PUT", "/guardrails/policy", () => json({ policy: {} })),
		);
		mount(<GuardrailPolicyEditor />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Add custom pattern/i }),
		);
		fireEvent.change(
			screen.getByLabelText(/Secrets and personal data pattern 1 name/i),
			{
				target: { value: "e" },
			},
		);
		fireEvent.change(
			screen.getByLabelText(/Secrets and personal data pattern 1 expression/i),
			{
				target: { value: "EMP-[0-9]{6}" },
			},
		);
		fireEvent.click(
			screen.getByRole("button", { name: /Save guardrail policy/i }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		const pii = (
			calls.find((c) => c.method === "PUT")?.body as {
				rails: { R2_secrets_pii: { pii: { classes: Record<string, string> } } };
			}
		).rails.R2_secrets_pii.pii;
		expect(pii.classes).toEqual({
			secrets: "block",
			email: "block",
			phone: "block",
			card: "block",
			ssn: "block",
		});
	});
});
