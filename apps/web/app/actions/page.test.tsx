import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(),
	requireSession: async () => ({ role: "owner" }),
}));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
}));
import { GatewayError, gatewayGet } from "@/lib/gateway";
import Loading from "./loading";
import Page from "./page";

const row = (over: Record<string, unknown> = {}) => ({
	action_id: "a1",
	occurred_at: "2026-11-09T10:42:03Z",
	tool_name: "release_payment",
	state: "awaiting_approval",
	evidence: {
		amount: { mode: "clear", value: { MinorUnits: 1500000 } },
		currency: { mode: "clear", value: { Currency: "USD" } },
		beneficiary_id: { mode: "tokenize", hmac: "ab12", last4: "T001" },
		memo: { mode: "digest_only", sha256: "cd34" },
	},
	...over,
});
const render = async (sp?: { before?: string }) =>
	renderToStaticMarkup(
		await Page({ searchParams: sp ? Promise.resolve(sp) : undefined }),
	);
beforeEach(() => vi.resetAllMocks());

it("renders action rows", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ actions: [row()] });
	const html = await render();
	for (const t of [
		"Nov 9, 2026 · 10:42 UTC",
		"release_payment",
		"Awaiting approval",
		"/actions/a1",
	])
		expect(html).toContain(t);
	expect(renderToStaticMarkup(<Loading />)).toContain("Loading");
});
it("formats minor units as currency", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ actions: [row()] });
	expect(await render()).toContain("$15,000.00");
});
it("shows tokenized evidence as last four", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		actions: [
			row({
				evidence: {
					amount: { mode: "clear", value: { MinorUnits: 1500000 } },
					currency: { mode: "clear", value: { Currency: "USD" } },
					b: { mode: "tokenize", hmac: "RAW-HMAC-VALUE", last4: "T001" },
				},
			}),
		],
	});
	const html = await render();
	expect(html).toContain("•••• T001");
	expect(html).not.toContain("RAW-HMAC-VALUE");
});
it("renders a real stored evidence map without leaking hashes", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ actions: [row()] });
	const html = await render();
	expect(html).toContain("$15,000.00");
	expect(html).toContain("•••• T001");
	for (const t of ["ab12", "cd34", "memo", "[object Object]"])
		expect(html).not.toContain(t);
});
it("falls back to minor units without exactly one currency", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		actions: [
			row({
				evidence: { amount: { mode: "clear", value: { MinorUnits: 1500000 } } },
			}),
		],
	});
	const html = await render();
	expect(html).toContain("1500000 (minor units)");
	expect(html).not.toContain("[object Object]");
});
it("renders older link from next_before", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		actions: [row()],
		next_before: 1040,
	});
	expect(await render()).toContain("/actions?before=1040");
	expect(vi.mocked(gatewayGet).mock.calls[0]?.[0]).not.toContain("limit=");
});
it("renders paused refusal row", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		actions: [row({ tool_name: null, state: "refused_paused", evidence: {} })],
	});
	const html = await render();
	expect(html).toContain("Refused — workspace paused");
	expect(html).toContain("—");
});
it("states coverage limit", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ actions: [] });
	expect(await render()).toContain(
		"Shows calls to protected tools that went through Tracelane. Calls that do not go through Tracelane are not seen.",
	);
});
it("renders empty state", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ actions: [] });
	expect(await render()).toContain(
		"No protected actions yet. Protected tools are configured with the policy API.",
	);
});
it("renders forbidden state", async () => {
	vi.mocked(gatewayGet).mockRejectedValue(new GatewayError(403, "no"));
	const html = await render();
	expect(html).toContain("Access denied");
	expect(html).not.toContain("No protected actions yet");
});
it("renders unavailable state", async () => {
	vi.mocked(gatewayGet).mockRejectedValue(new GatewayError(503, "down"));
	const html = await render();
	expect(html).toContain("Couldn&#x27;t load actions");
	expect(html).toContain("Retry");
	expect(html).not.toContain("No protected actions yet");
});
it("renders action control off", async () => {
	vi.mocked(gatewayGet).mockRejectedValue(new GatewayError(409, "off"));
	expect(await render()).toContain("Action control is off for this workspace.");
});
it("needs review never styled as success", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		actions: [row({ state: "needs_review" })],
	});
	const html = await render();
	expect(html).toContain("Needs review");
	expect(html).toContain("bg-warn-soft");
	expect(html).not.toContain("bg-ok-soft");
});

it("flags an action with an unreadable event", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		actions: [row({ state: "needs_review", malformed: true })],
	});
	const html = await render();
	expect(html).toContain("Unreadable event");
	expect(html).toContain("Needs review");
});
it("says when unreadable action records were left out", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		actions: [row()],
		skipped_malformed: 2,
	});
	expect(await render()).toContain(
		"2 action record(s) on this page could not be read",
	);
});
it("shows no unreadable notes on a clean page", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ actions: [row()] });
	const html = await render();
	expect(html).not.toContain("Unreadable event");
	expect(html).not.toContain("could not be read");
});
