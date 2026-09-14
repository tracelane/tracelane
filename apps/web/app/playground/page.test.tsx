/**
 * OBS-16 proof #4: a tenant with zero connected providers gets a disabled
 * surface and the page makes NO gateway call that could run a prompt — the
 * chat-completions route is never reached because the form itself never
 * mounts. `@/lib/auth` and `@/lib/gateway` are mocked wholesale (never a real
 * network, `.claude/rules/testing.md`) — mocking `@/lib/auth` also avoids
 * pulling in `@workos-inc/authkit-nextjs`, whose `next/cache` subpath import
 * does not resolve under Vitest (the same reason
 * `sessions-agent-chip-render.test.tsx` imports `SessionRow` rather than the
 * page module it lives on).
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
	GatewayError: h.FakeGatewayError,
}));

import PlaygroundPage from "./page";

beforeEach(() => {
	h.role = "owner";
	h.gatewayGet.mockReset();
});

describe("PlaygroundPage — no connected provider (owner)", () => {
	it("renders the disabled/no-provider state and makes exactly ONE gateway call — the key list, never chat completions", async () => {
		h.gatewayGet.mockResolvedValue([]);
		const el = await PlaygroundPage();
		const html = renderToStaticMarkup(el);

		expect(html).toContain("Connect a provider to run prompts");
		expect(html).not.toContain("<select"); // the form never mounts
		expect(html).toContain("/settings/providers");
		expect(h.gatewayGet).toHaveBeenCalledTimes(1);
		expect(h.gatewayGet).toHaveBeenCalledWith("/v1/byok/provider-keys");
	});

	it("degrades to the same no-provider state when the gateway is unreachable, without throwing", async () => {
		h.gatewayGet.mockRejectedValue(new h.FakeGatewayError(503, "unreachable"));
		const el = await PlaygroundPage();
		const html = renderToStaticMarkup(el);
		expect(html).toContain("Connect a provider to run prompts");
	});
});

describe("PlaygroundPage — member/viewer cannot list provider keys", () => {
	it("never calls the gateway (avoids the owner-only 403) and shows the locked state, not the no-provider message", async () => {
		h.role = "member";
		const el = await PlaygroundPage();
		const html = renderToStaticMarkup(el);

		expect(html).toContain("owner-only");
		expect(html).not.toContain("Connect a provider to run prompts");
		expect(h.gatewayGet).not.toHaveBeenCalled();
	});
});

describe("PlaygroundPage — a connected provider", () => {
	it("renders the form with a model derived from the anchored default-model map", async () => {
		h.gatewayGet.mockResolvedValue([
			{ provider_id: "anthropic", last4: "abcd" },
		]);
		const el = await PlaygroundPage();
		const html = renderToStaticMarkup(el);

		expect(html).toContain("<select");
		expect(html).toContain("claude-sonnet-4-6");
		expect(html).not.toContain("Connect a provider to run prompts");
	});
});
