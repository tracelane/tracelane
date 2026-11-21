// @vitest-environment jsdom
import { cleanup, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GATEWAY_SLOTS } from "../../lib/gateway-controls";
import { SlotView } from "./SlotView";
import { json, mockFetch, mount, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const responses: Record<string, unknown> = {
	mcp: {
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
	},
	approvals: { approvals: [], pending: 0, next_cursor: null },
	"protected-tools": { policies: [] },
	"data-controls": {
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
	},
	routing: {
		doc: {},
		version: 0,
		valid: true,
		can_edit: true,
		limits: {
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
				match_header_denylist: ["authorization"],
			},
			breaker: {
				consecutive_failures_min: 1,
				consecutive_failures_max: 10,
				cooldown_secs_min: 1,
				cooldown_secs_max: 300,
			},
			timeouts: { min_ms: 1, total_min_ms: 1, max_ms: 1000, max_rules: 2 },
		},
	},
	cache: {
		plan: { cache_control: true, ttl_hours: 24 },
		settings: {
			mode: { value: "inherit", source: "default" },
			ttl_hours: { value: null, source: "default" },
			namespace_by: { value: "workspace", source: "default" },
			semantic: { value: false, source: "default" },
			updated_at: null,
		},
		effective: {
			enabled: true,
			why_off: null,
			ttl_hours: 24,
			ttl_source: "plan",
			ttl_ceiling_hours: 720,
		},
		epochs: [],
		stats: {
			window_hours: 24,
			hits: 0,
			cost_saved_usd: 0,
			stats_unavailable: false,
		},
	},
	otel: { exports: [], plan: { export_enabled: true, max_exports: 3 } },
	guardrails: {
		policy: null,
		effective: {},
		etag: `"${"0".repeat(64)}"`,
		can_edit: true,
	},
	"guardrail-integrations": { hooks: [] },
};

async function checkTab(slot: (typeof GATEWAY_SLOTS)[number]) {
	mockFetch(
		when("GET", `/${slot.probe}`, () => json(responses[slot.id])),
		when("GET", "/mcp-servers", () => json({ servers: [], limits: {} })),
		when("GET", "/mcp-tools", () => json({ tools: [] })),
		when("GET", "/mcp-policy/preview", () =>
			json({ would_block: null, stats_unavailable: true }),
		),
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
				limits: { max_ttl_secs: 86400, tool_glob_max_chars: 128 },
			}),
		),
	);
	mount(<SlotView slot={slot} />);
	if (slot.id === "cache") await screen.findByTestId("cache-effective");
	else if (slot.id === "otel") await screen.findByText(/No exports/);
	else if (slot.id === "mcp")
		await screen.findByRole("button", { name: "Save tool policy" });
	else if (slot.id === "approvals")
		await screen.findByText("No pending requests.");
	else if (slot.id === "protected-tools")
		await screen.findByText(/No protected-tool policies are active/);
	else if (slot.id === "guardrail-integrations")
		await screen.findByRole("button", { name: "Add integration" });
	else
		await screen.findByRole("button", {
			name: /Save (routing|guardrail policy|retention)/i,
		});

	const copy = document.body.textContent ?? "";
	expect(copy).not.toMatch(/\b(OG|GWY|OBS|DSH|PLT|AUD|SRE|BILL|GOV|SEC)-\d+\b/);
	expect(copy).not.toMatch(
		/\b(?:A(?:1|2|13)|SRE#\d+|SRE-DEP-\d+|PLT-N\d+|GWY-C\d+)\b/,
	);
	expect(copy).not.toMatch(/not built yet|TODO/i);
}

it("every Gateway slot renders without internal copy", async () => {
	for (const slot of GATEWAY_SLOTS) {
		await checkTab(slot);
		cleanup();
		vi.unstubAllGlobals();
	}
});
