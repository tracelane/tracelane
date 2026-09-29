import { Children, type ReactNode, isValidElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
	class GatewayError extends Error {
		constructor(public status: number) {
			super(String(status));
		}
	}
	return { gatewayGet: vi.fn(), GatewayError };
});
vi.mock("@/lib/gateway", () => ({ ...h, gatewayGetText: vi.fn() }));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "org_test", role: "owner" }),
	canAdmin: () => true,
}));
vi.mock("@/db", () => ({
	db: {
		select: () => ({
			from: () => ({
				where: () => ({
					limit: async () => [
						{
							id: "tenant",
							plan: "free",
							pubkey: "",
							createdAt: new Date("2026-09-20T00:00:00Z"),
						},
					],
				}),
			}),
		}),
	},
}));
vi.mock("@/lib/entitlements", () => ({
	resolveEntitlements: async () => ({
		audit_self_verify: true,
		audit_ledger: false,
	}),
}));
vi.mock("@/lib/e2e-audit-fixture", () => ({
	e2eAuditFixture: async () => null,
}));

import AuditPage from "./audit/page";
import ComparePage from "./traces/compare/page";

beforeEach(() => {
	h.gatewayGet.mockReset();
});

it.each([401, 403, 503])(
	"trace picker failure %i never states the workspace has one trace",
	async (status) => {
		h.gatewayGet.mockRejectedValue(new h.GatewayError(status));
		const html = renderToStaticMarkup(
			await ComparePage({ searchParams: Promise.resolve({ a: "trace-a" }) }),
		);
		expect(html).not.toContain("Only one trace");
		expect(html).not.toContain("No other traces to compare against");
		expect(html).toContain(
			status === 401
				? "Sign in"
				: status === 403
					? "Access denied"
					: "Couldn&#x27;t load recent traces",
		);
		expect(html).toContain(
			status === 401 ? "/sign-in" : "/traces/compare?a=trace-a",
		);
	},
);

it("trace picker success-empty describes only the bounded recent list", async () => {
	h.gatewayGet.mockResolvedValue({
		traces: [{ trace_id: "trace-a", root_name: "A" }],
	});
	const html = renderToStaticMarkup(
		await ComparePage({ searchParams: Promise.resolve({ a: "trace-a" }) }),
	);
	expect(html).toContain("No other traces in this recent list");
	expect(html).not.toContain("Only one trace");
});

it("trace picker links a successfully loaded second trace", async () => {
	h.gatewayGet.mockResolvedValue({
		traces: [{ trace_id: "trace-b", root_name: "B" }],
	});
	const html = renderToStaticMarkup(
		await ComparePage({ searchParams: Promise.resolve({ a: "trace-a" }) }),
	);
	expect(html).toContain("/traces/compare?a=trace-a&amp;b=trace-b");
});

// Resolve the async server child behind the real page's Suspense boundary.
async function auditContent(): Promise<string> {
	const page = await AuditPage({ searchParams: Promise.resolve({}) });
	function find(node: ReactNode): ReactNode {
		for (const child of Children.toArray(node)) {
			if (!isValidElement<{ children?: ReactNode }>(child)) continue;
			if (typeof child.type === "function" && child.type.name === "LedgerData")
				return child;
			const found = find(child.props.children);
			if (found) return found;
		}
		return null;
	}
	const child = find(page);
	if (!isValidElement(child) || typeof child.type !== "function")
		throw new Error("Audit evidence server child missing");
	const component = child.type as (props: unknown) => Promise<ReactNode>;
	return renderToStaticMarkup(await component(child.props));
}

it.each([401, 403, 503])(
	"self-verification failure %i never claims an empty ledger",
	async (status) => {
		h.gatewayGet.mockRejectedValue(new h.GatewayError(status));
		const html = await auditContent();
		expect(html).not.toContain("No events in this ledger");
		expect(html).toContain("We couldn’t check your evidence");
		expect(html).toContain("CANNOT DETERMINE");
		expect(html).toContain("Audit workflow");
		expect(html).toContain(
			status === 401
				? "/sign-in"
				: status === 403
					? "does not have permission"
					: "integrity is unknown",
		);
	},
);
it("only a successful zero inventory read presents an empty workspace", async () => {
	h.gatewayGet.mockImplementation(async (path: string) =>
		path.includes("ledger-range") ? { total: 0 } : { chain_ndjson: "" },
	);
	expect(await auditContent()).toContain("No events in this ledger");
	expect(h.gatewayGet).toHaveBeenCalledWith(
		"/v1/audit/self-verify?limit=1000&order=desc",
	);
});
it("empty loaded window with a nonempty inventory is unknown", async () => {
	h.gatewayGet.mockImplementation(async (path: string) =>
		path.includes("ledger-range")
			? { total: 1_000_000_000, to: 999_999_999 }
			: { chain_ndjson: "" },
	);
	const html = await auditContent();
	expect(html).toContain("No evidence loaded. Integrity is unknown.");
	expect(html).not.toContain("No events in this ledger");
});
it("a failed lifetime inventory cannot substitute the retention-window count", async () => {
	h.gatewayGet.mockImplementation(async (path: string) => {
		if (path.includes("ledger-range")) throw new h.GatewayError(503);
		return {
			chain_ndjson: '{"seq":0,"event_type":"call"}\n',
			total_in_window: 1,
		};
	});
	const html = await auditContent();
	expect(html).toContain("Unavailable");
	expect(html).toContain("Rows outside this window are not counted here");
	expect(html).not.toContain("0 rows outside");
});
it("a populated response uses the bounded view, never a render-time export", async () => {
	h.gatewayGet.mockImplementation(async (path: string) =>
		path.includes("ledger-range")
			? { total: 1, to: 0 }
			: { chain_ndjson: '{"seq":0,"event_type":"call"}\n' },
	);
	expect(await auditContent()).toContain("Batch evidence");
	expect(h.gatewayGet.mock.calls.map((c) => c[0])).toEqual([
		"/v1/audit/self-verify?limit=1000&order=desc",
		"/v1/audit/ledger-range",
	]);
});
