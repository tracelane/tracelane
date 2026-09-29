/**
 * OBS-16 proof #4 + `EVL-03` §2/§7 proof 5: a tenant with zero connected
 * providers gets a disabled surface and the page makes NO gateway call that
 * could run a prompt — the chat-completions route is never reached because
 * the form itself never mounts. `@/lib/auth`, `@/lib/gateway` and
 * `@/lib/playground-settings` are mocked wholesale (never a real network,
 * `.claude/rules/testing.md`) — mocking `@/lib/auth` also avoids pulling in
 * `@workos-inc/authkit-nextjs`, whose `next/cache` subpath import does not
 * resolve under Vitest (the same reason `sessions-agent-chip-render.test.tsx`
 * imports `SessionRow` rather than the page module it lives on).
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
	default: ({ href, children, ...rest }: Record<string, unknown>) =>
		createElement("a", { href, ...rest }, children as never),
}));

// `class FakeGatewayError` lives INSIDE the hoisted block, not beside it —
// `vi.mock` factories are hoisted above the rest of the file, so a plain
// `class` declared below them is still in its temporal dead zone when the
// factory first runs.
const h = vi.hoisted(() => {
	class FakeGatewayError extends Error {
		readonly status: number;
		readonly body: Record<string, unknown> | null;
		constructor(
			status: number,
			message: string,
			body: Record<string, unknown> | null = null,
		) {
			super(message);
			this.status = status;
			this.body = body;
		}
	}
	return {
		role: "owner" as string | null,
		gatewayGet: vi.fn(),
		gatewayGetOrNull: vi.fn(async (_path: string) => null as unknown),
		FakeGatewayError,
	};
});

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_TEST",
		userId: "user_1",
		email: "a@b.com",
		role: h.role,
	})),
	// Real predicate (`crates/gateway/src/auth/mod.rs::can_admin` mirror) —
	// re-declared here because the whole module is mocked.
	canAdmin: (role: string | null | undefined) =>
		role === "owner" || role === "admin",
}));

vi.mock("@/lib/gateway", () => ({
	gatewayGet: (...args: unknown[]) => h.gatewayGet(...(args as [string])),
	gatewayGetOrNull: (...args: unknown[]) =>
		h.gatewayGetOrNull(...(args as [string])),
	GatewayError: h.FakeGatewayError,
}));

vi.mock("@/lib/playground-settings", () => ({
	getPlaygroundSettings: async () => ({
		limits: {
			max_columns: 4,
			max_messages: 50,
			max_body_bytes: 262144,
			max_tokens_cap: 2048,
			timeout_ms: 45000,
			cost_poll_seconds: 20,
			history_entries: 10,
		},
		defaulted: false,
	}),
}));

import PlaygroundPage from "./page";

function sp(params: Record<string, string> = {}) {
	return { searchParams: Promise.resolve(params) };
}

beforeEach(() => {
	h.role = "owner";
	h.gatewayGet.mockReset();
	h.gatewayGetOrNull.mockReset();
	h.gatewayGetOrNull.mockResolvedValue(null);
});

describe("PlaygroundPage — no connected provider (owner)", () => {
	it("renders the disabled/no-provider state and makes exactly ONE gateway call — the key list, never chat completions", async () => {
		h.gatewayGet.mockResolvedValue([]);
		const el = await PlaygroundPage(sp());
		const html = renderToStaticMarkup(el);

		expect(html).toContain("Connect a provider to run prompts");
		expect(html).not.toContain("<select"); // the form never mounts
		expect(html).toContain("/settings/providers");
		expect(h.gatewayGet).toHaveBeenCalledTimes(1);
		expect(h.gatewayGet).toHaveBeenCalledWith("/v1/byok/provider-keys");
	});

	it("distinguishes an unreachable provider list from an empty list", async () => {
		h.gatewayGet.mockRejectedValue(new h.FakeGatewayError(503, "unreachable"));
		const el = await PlaygroundPage(sp());
		const html = renderToStaticMarkup(el);
		expect(html).toContain("Couldn&#x27;t load connected providers");
		expect(html).not.toContain("Connect a provider to run prompts");
		expect(html).toContain('href="/playground"');
	});
});

describe("PlaygroundPage — member/viewer cannot list provider keys", () => {
	it.each([401, 403])(
		"keeps authorization failure %i distinct from no providers",
		async (status) => {
			h.gatewayGet.mockRejectedValue(new h.FakeGatewayError(status, "denied"));
			const html = renderToStaticMarkup(await PlaygroundPage(sp()));
			expect(html).toContain(status === 401 ? "Sign in" : "Access denied");
			expect(html).not.toContain("Connect a provider to run prompts");
		},
	);

	it("never calls the gateway (avoids the owner-only 403) and allows typing a model without implying no providers", async () => {
		h.role = "member";
		const el = await PlaygroundPage(sp());
		const html = renderToStaticMarkup(el);

		expect(html).toContain("type a model id");
		expect(html).toContain('aria-label="Model 1"');
		expect(html).not.toContain("Connect a provider to run prompts");
		expect(h.gatewayGet).not.toHaveBeenCalled();
	});
});

describe("PlaygroundPage — a connected provider", () => {
	it("renders the form with a model derived from the anchored default-model map", async () => {
		h.gatewayGet.mockResolvedValue([
			{ provider_id: "anthropic", last4: "abcd" },
		]);
		const el = await PlaygroundPage(sp());
		const html = renderToStaticMarkup(el);

		expect(html).toContain("<select");
		expect(html).toContain("claude-sonnet-4-6");
		expect(html).not.toContain("Connect a provider to run prompts");
	});

	it("with no trace/span params, never calls the spans read at all", async () => {
		h.gatewayGet.mockResolvedValue([
			{ provider_id: "anthropic", last4: "abcd" },
		]);
		await PlaygroundPage(sp());
		expect(h.gatewayGetOrNull).not.toHaveBeenCalled();
	});
});

// ── `?trace=&span=` — the "Open in playground" prefill (spec §2, §7 proof 1/5) ──

function spanFixture(attributes: Record<string, unknown>, spanId = "9f3a0000") {
	return {
		span_id: spanId,
		parent_span_id: null,
		name: "gen_ai.chat",
		start_time: "2026-09-27T00:00:00",
		end_time: "2026-09-27T00:00:01",
		duration_us: 900_000,
		status_code: 0,
		status_message: "",
		attributes: JSON.stringify(attributes),
		aft_ids: [],
		intervention: 0,
	};
}

describe("PlaygroundPage — ?trace=&span= prefill", () => {
	beforeEach(() => {
		h.gatewayGet.mockResolvedValue([
			{ provider_id: "anthropic", last4: "abcd" },
		]);
	});

	it("reads GET /v1/traces/{trace}/spans and restores the model into the form (proof 1)", async () => {
		h.gatewayGetOrNull.mockResolvedValue([
			spanFixture({ gen_ai_request_model: "claude-sonnet-4-6" }, "9f3a0000"),
		]);
		const html = renderToStaticMarkup(
			await PlaygroundPage(sp({ trace: "1c2d0000", span: "9f3a0000" })),
		);
		expect(h.gatewayGetOrNull).toHaveBeenCalledWith(
			"/v1/traces/1c2d0000/spans",
		);
		expect(html).toContain("Restored from span");
		expect(html).toContain("9f3a0000");
	});

	it("404 (gatewayGetOrNull → null): 'not in this workspace', form still renders empty (spec §7 proof 5)", async () => {
		h.gatewayGetOrNull.mockResolvedValue(null);
		const html = renderToStaticMarkup(
			await PlaygroundPage(sp({ trace: "otherTenantTrace", span: "9f3a0000" })),
		);
		expect(html).toContain("isn&#x27;t in this workspace");
		expect(html).toContain("<select"); // the form is still usable, per spec §4
	});

	it("a span id absent from a real trace's spans reads the SAME as 404 — never distinguished", async () => {
		h.gatewayGetOrNull.mockResolvedValue([spanFixture({}, "some-other-span")]);
		const html = renderToStaticMarkup(
			await PlaygroundPage(sp({ trace: "1c2d0000", span: "9f3a0000" })),
		);
		expect(html).toContain("isn&#x27;t in this workspace");
	});

	it("a gateway read failure (503) shows a retry banner, form still usable (spec §4)", async () => {
		h.gatewayGetOrNull.mockRejectedValue(
			new h.FakeGatewayError(503, "unreachable"),
		);
		const html = renderToStaticMarkup(
			await PlaygroundPage(sp({ trace: "1c2d0000", span: "9f3a0000" })),
		);
		expect(html).toContain("Couldn&#x27;t load the source span");
		expect(html).toContain("<select");
	});
});
