import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@/lib/gateway", () => ({ gatewayGet: vi.fn() }));
import { gatewayGet } from "@/lib/gateway";
import { CoveragePanel, loadCoverage } from "./CoveragePanel";

const S1 = "11111111-1111-4111-8111-111111111111";
const render = async () =>
	renderToStaticMarkup(<CoveragePanel coverage={await loadCoverage()} />);
beforeEach(() => vi.resetAllMocks());

function serve(opts: {
	tools?: unknown;
	policies?: unknown;
	detail?: (ref: string) => unknown;
}) {
	vi.mocked(gatewayGet).mockImplementation(async (path: string) => {
		if (path === "/v1/mcp-tools") return { tools: opts.tools ?? [] } as never;
		if (path === "/v1/action-policies")
			return { policies: opts.policies ?? [] } as never;
		const d = opts.detail?.(decodeURIComponent(path.split("/").pop() ?? ""));
		if (d instanceof Error) throw d;
		return d as never;
	});
}

it("shows protected and observed-only tools with the required sentence", async () => {
	serve({
		tools: [
			{ server_id: S1, server_name: "Pay", tool_name: "release_payment" },
			{ server_id: S1, server_name: "Pay", tool_name: "list_invoices" },
		],
		policies: [{ tool_ref: "r1", server_id: S1, tool_name: "release_payment" }],
		detail: () => ({ contract_jcs: '{"protected":true}' }),
	});
	const html = await render();
	expect(html).toContain("1 of 2 tools seen through Tracelane is protected");
	expect(html).toContain("Protected");
	expect(html).toContain("Observed only");
	expect(html).toContain(
		"Calls that do not go through Tracelane are not seen.",
	);
});
it("a failed read says it could not load, never zero coverage", async () => {
	vi.mocked(gatewayGet).mockRejectedValue(new Error("down"));
	const html = await render();
	expect(html).toContain("Coverage could not be loaded.");
	expect(html).toContain("not seen.");
	expect(html).not.toContain("No tools have been seen");
});
it("an unexpected payload shape is treated as a failed read", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ actions: [] } as never);
	expect(await render()).toContain("Coverage could not be loaded.");
});
it("an unreadable contract is Could not check, not Protected", async () => {
	serve({
		tools: [
			{ server_id: S1, server_name: "Pay", tool_name: "release_payment" },
		],
		policies: [{ tool_ref: "r1", server_id: S1, tool_name: "release_payment" }],
		detail: () => new Error("boom"),
	});
	const html = await render();
	expect(html).toContain("Could not check");
	expect(html).not.toContain(">Protected<");
});
it("no tools yet says so", async () => {
	serve({});
	expect(await render()).toContain(
		"No tools have been seen through Tracelane yet.",
	);
});
it("states a protected tool not yet seen", async () => {
	serve({
		policies: [
			{ tool_ref: "r1", server_id: S1, tool_name: "export_customers" },
		],
		detail: () => ({ contract_jcs: '{"protected":true}' }),
	});
	expect(await render()).toContain("not seen yet");
});
it("reads at most 25 contracts and says how many were not checked", async () => {
	const policies = Array.from({ length: 30 }, (_, i) => ({
		tool_ref: `r${i}`,
		server_id: S1,
		tool_name: `t${i}`,
	}));
	serve({ policies, detail: () => ({ contract_jcs: '{"protected":true}' }) });
	const html = await render();
	const details = vi
		.mocked(gatewayGet)
		.mock.calls.filter(([p]) => String(p).startsWith("/v1/action-policies/"));
	expect(details).toHaveLength(25);
	expect(html).toContain("5 more tool policies were not checked on this page.");
});
it("one readable and one unreadable contract are labelled separately", async () => {
	serve({
		tools: [
			{ server_id: S1, server_name: "Pay", tool_name: "a" },
			{ server_id: S1, server_name: "Pay", tool_name: "b" },
		],
		policies: [
			{ tool_ref: "ra", server_id: S1, tool_name: "a" },
			{ tool_ref: "rb", server_id: S1, tool_name: "b" },
		],
		detail: (ref) =>
			ref === "ra" ? { contract_jcs: '{"protected":true}' } : new Error("down"),
	});
	const html = await render();
	expect(html).toContain("Protected");
	expect(html).toContain("Could not check");
	expect(html).not.toContain("not checked on this page");
});
it("never has more than 6 contract reads in flight", async () => {
	let inFlight = 0;
	let peak = 0;
	const policies = Array.from({ length: 20 }, (_, i) => ({
		tool_ref: `r${i}`,
		server_id: S1,
		tool_name: `t${i}`,
	}));
	vi.mocked(gatewayGet).mockImplementation(async (path: string) => {
		if (path === "/v1/mcp-tools") return { tools: [] } as never;
		if (path === "/v1/action-policies") return { policies } as never;
		inFlight += 1;
		peak = Math.max(peak, inFlight);
		await new Promise((r) => setTimeout(r, 1));
		inFlight -= 1;
		return { contract_jcs: '{"protected":true}' } as never;
	});
	await render();
	expect(peak).toBeLessThanOrEqual(6);
	expect(peak).toBeGreaterThan(1);
});
it("a malformed tool entry reads as could not be loaded, never a rejection", async () => {
	serve({ tools: [null], policies: [] });
	await expect(loadCoverage()).resolves.toBeNull();
});
