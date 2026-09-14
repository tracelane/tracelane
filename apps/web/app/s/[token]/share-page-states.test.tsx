/**
 * `OBS-48` — the public share page's failure states must NOT collapse into
 * one message. Spec §4 draws a hard line: "Public: gateway error" is
 * explicitly NOT the 404 copy (TRAPS §18: error ≠ empty), and the rate-limit
 * copy is a third, distinct sentence again. A page that rendered the same
 * "unavailable" text for all three would look identical whether the link was
 * revoked, the gateway was down, or the visitor was throttled — three
 * different facts a customer needs told apart.
 *
 * `next/navigation` is aliased (see `vitest.config.ts`) to a stub whose
 * `notFound()` THROWS — matching the real Next.js behavior closely enough
 * that `page.tsx`'s not-found branch is observable as a thrown error here,
 * without needing a real Next router.
 *
 * `@/lib/gateway` is mocked down to just `gatewayBaseUrl` — the ONLY export
 * `page.tsx` uses (it deliberately never calls `gatewayGet`/`requireGatewayToken`,
 * see the file's own header comment on why). The real module's top-level
 * `import { requireGatewayToken } from "@/lib/auth"` pulls in
 * `@workos-inc/authkit-nextjs`, which does not resolve under vitest's `node`
 * environment (`next/cache` subpath export) — an unrelated, pre-existing
 * limitation of importing that package outside a real Next runtime, not a
 * defect in this route.
 */

import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/gateway", () => ({
	gatewayBaseUrl: () => "http://localhost:9999",
}));

function jsonResponse(status: number, body: unknown, headers?: HeadersInit) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});
}

const SHARE_OK_BODY = {
	trace_id: "t1",
	root_name: "planner.run",
	shared_at: "2026-09-01T00:00:00Z",
	expires_at: "2026-10-01T00:00:00Z",
	span_count: 1,
	spans: [
		{
			span_id: "s1",
			parent_span_id: null,
			name: "planner.run",
			start_time: "2026-09-01T00:00:00",
			end_time: "2026-09-01T00:00:01",
			duration_us: 1_000_000,
			status_code: 0,
			status_message: "",
			attributes: "{}",
			aft_ids: [],
			intervention: 0,
		},
	],
	chain: { chained: true, seq: 42, anchored: false },
	workspace_name: "acme-workspace",
};

describe("SharedTracePage failure-state copy", () => {
	it("a gateway 404 throws through notFound() — the not-found route, never the error copy", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => jsonResponse(404, { error: "not_found" })),
		);
		const { default: SharedTracePage } = await import("./page");
		await expect(
			SharedTracePage({ params: Promise.resolve({ token: "gone" }) }),
		).rejects.toThrow("not_found");
		vi.unstubAllGlobals();
	});

	it("a non-404 gateway failure renders the ERROR copy, distinct from the 404 copy", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => jsonResponse(503, { error: "unavailable" })),
		);
		const { default: SharedTracePage } = await import("./page");
		const element = await SharedTracePage({
			params: Promise.resolve({ token: "x" }),
		});
		const { renderToStaticMarkup } = await import("react-dom/server");
		const html = renderToStaticMarkup(element);
		expect(html).toContain("Could not load this trace right now");
		// Never the 404 sentence — an outage must not read as "revoked".
		expect(html).not.toContain("expired or was revoked");
		vi.unstubAllGlobals();
	});

	it("a 429 renders the rate-limit copy — a third, distinct sentence", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () =>
				jsonResponse(429, { error: "rate_limited" }, { "retry-after": "60" }),
			),
		);
		const { default: SharedTracePage } = await import("./page");
		const element = await SharedTracePage({
			params: Promise.resolve({ token: "x" }),
		});
		const { renderToStaticMarkup } = await import("react-dom/server");
		const html = renderToStaticMarkup(element);
		expect(html).toContain("Too many requests, try again in a minute.");
		expect(html).not.toContain("Could not load this trace right now");
		expect(html).not.toContain("expired or was revoked");
		vi.unstubAllGlobals();
	});

	it("the not-found ROUTE renders the exact spec §4 sentence", async () => {
		const { default: SharedTraceNotFound } = await import("./not-found");
		const { renderToStaticMarkup } = await import("react-dom/server");
		const html = renderToStaticMarkup(SharedTraceNotFound());
		expect(html).toContain(
			"This shared trace has expired or was revoked. Ask the owner for a new link.",
		);
	});

	it("a healthy share renders the trace, not any failure copy", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => jsonResponse(200, SHARE_OK_BODY)),
		);
		const { default: SharedTracePage } = await import("./page");
		const element = await SharedTracePage({
			params: Promise.resolve({ token: "ok" }),
		});
		const { renderToStaticMarkup } = await import("react-dom/server");
		const html = renderToStaticMarkup(element);
		expect(html).toContain("planner.run");
		expect(html).toContain("acme-workspace");
		expect(html).not.toContain("Could not load this trace right now");
		expect(html).not.toContain("expired or was revoked");
		vi.unstubAllGlobals();
	});
});
