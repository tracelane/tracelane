import { PROVIDERS } from "@/components/settings/provider-catalog.generated";
import { identityForKey, providerIdentity } from "@/lib/kya/identity";
import type { Activity, ActivityLoad, ActivityResponse } from "@/lib/kya/types";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ActivityView } from "./ActivityView";
import { IdentityAvatar } from "./IdentityAvatar";

const activity: Activity = {
	key: "claude-code",
	raw_key: "claude-code",
	calls: 3,
	traces: 2,
	tokens_in: 20,
	tokens_out: 12,
	input_usage_missing: 1,
	output_usage_missing: 0,
	cost_usd: 1.25,
	unpriced_calls: 1,
	errors: 1,
	error_rate: 1 / 3,
	p50_us: 2000000,
	p95_us: 2900000,
	first_seen_us: 1800000000000000,
	last_seen_us: 1800000000000000,
	share_of_workspace: 0.75,
	sources: [{ key: "header", calls: 3 }],
	providers: ["anthropic"],
	cross_list: [{ key: "claude-haiku-4-5", calls: 2 }],
	cross_count: 1,
	tools: [],
	tool_count: 0,
	recent_traces: [{ trace_id: "trace-1", last_seen_us: 1800000000000000 }],
};
const data: ActivityResponse = {
	kind: "agent",
	requested_days: 7,
	window_days: 7,
	retention_days: 30,
	since_us: 1799395200000000,
	until_us: 1800000000000000,
	workspace_calls: 4,
	has_retained_activity: true,
	total_identities: 1,
	truncated: false,
	identities: [activity],
};
function render(result: ActivityLoad, profileKey?: string) {
	return renderToStaticMarkup(
		<ActivityView
			kind="agent"
			window="7d"
			profileKey={profileKey}
			result={result}
			onRetry={() => {}}
		/>,
	);
}

describe("identity activity states", () => {
	it("gives new workspaces both supported naming instructions", () => {
		const html = render({
			status: "ready",
			data: { ...data, identities: [], has_retained_activity: false },
		});
		expect(html).toContain("No agent activity yet");
		expect(html).toContain("gen_ai.agent.name");
		expect(html).toContain("x-tracelane-agent-name");
	});
	it("distinguishes a filtered window, an outage and a forbidden read", () => {
		expect(
			render({ status: "ready", data: { ...data, identities: [] } }),
		).toContain("No agents in the last 7 days");
		expect(render({ status: "error", code: 503 })).toContain(
			"Your traces are unaffected",
		);
		expect(render({ status: "error", code: 403 })).toContain(
			"access to traces in this workspace",
		);
		expect(render({ status: "loading" })).toContain("Loading activity");
	});
	it("shows source, missing usage, exact cost and a working profile destination", () => {
		const html = render({ status: "ready", data });
		expect(html).toContain("$1.25");
		expect(html).toContain("1 call unpriced");
		expect(html).toContain("agent name from header");
		expect(html).toContain("/agents/agent/claude-code");
		expect(html).not.toMatch(/\b(verified|attested|signed)\b/i);
	});
	it("keeps totals when a profile list fails and offers retry", () => {
		const html = render(
			{
				status: "ready",
				data: { ...data, identities: [{ ...activity, cross_list: null }] },
			},
			"claude-code",
		);
		expect(html).toContain("$1.25");
		expect(html).toContain("Couldn&#x27;t load");
		expect(html).toContain("Retry");
		expect(html).toContain("No tool calls recorded");
	});
	it("explains direct calls and never presents absent usage as measured zero", () => {
		const html = render({
			status: "ready",
			data: {
				...data,
				identities: [
					{
						...activity,
						key: "~direct",
						raw_key: "",
						tokens_in: null,
						tokens_out: null,
						cost_usd: null,
						sources: [{ key: "direct", calls: 3 }],
					},
				],
			},
		});
		expect(html).toContain("Direct API calls");
		expect(html).toContain("Name your agent");
		expect(html).not.toContain("$0.00");
	});
	it("discloses unknown identities, retention clipping and the full identity count", () => {
		const html = render({
			status: "ready",
			data: {
				...data,
				requested_days: 30,
				window_days: 7,
				retention_days: 7,
				total_identities: 205,
				truncated: true,
				identities: [
					{ ...activity, key: "our-custom-agent", raw_key: "our-custom-agent" },
				],
			},
		});
		expect(html).toContain("Not in our catalog yet");
		expect(html).toContain("your plan keeps 7");
		expect(html).toContain("of 205");
	});
});

describe("one avatar on every surface", () => {
	it("renders all three sizes and an accessible profile link", () => {
		for (const size of [24, 40, 96] as const) {
			const html = renderToStaticMarkup(
				<IdentityAvatar
					identity={identityForKey("agent", "claude-code")}
					size={size}
				/>,
			);
			expect(html).toContain("/agents/agent/claude-code");
			expect(html).toContain(`width:${size}px`);
			expect(html).toContain("Claude Code");
		}
	});
	it("every supported provider has a visible avatar", () => {
		for (const provider of PROVIDERS) {
			const html = renderToStaticMarkup(
				<IdentityAvatar
					identity={providerIdentity(provider.id)}
					link={false}
				/>,
			);
			expect(html, provider.id).not.toBe("");
		}
	});
});

it("avatar and related-identity links retain the selected 30-day window", () => {
	for (const profileKey of [undefined, "claude-code"]) {
		const html = renderToStaticMarkup(
			<ActivityView
				kind="agent"
				window="30d"
				profileKey={profileKey}
				result={{ status: "ready", data }}
				onRetry={() => {}}
			/>,
		);
		expect(html).toContain('href="/agents/model/claude-haiku-4-5?window=30d"');
		if (!profileKey)
			expect(
				html.match(/href="\/agents\/agent\/claude-code\?window=30d"/g),
			).toHaveLength(2);
	}
});
