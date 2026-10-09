/**
 * Tests for GET /api/traces/export — the trace CSV/JSON export proxy.
 *
 * Asserts: mints the per-user JWT (never a request-supplied tenant), translates
 * the page filters (status→has_error, range→since) to gateway params, forwards
 * `format`, and returns the file with a Content-Disposition attachment. Gateway
 * fetch + auth mocked (off the network).
 */

import { TRACE_EXPORT_PARAMS } from "@/app/traces/filter-registry";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({})),
	requireGatewayToken: vi.fn(async () => ({
		token: "wos_jwt_user_a",
		tenantId: "org_A",
	})),
}));

import { GET } from "./route";

const fetchMock = vi.fn();

function req(qs: string) {
	return {
		nextUrl: new URL(`https://app.example/api/traces/export?${qs}`),
	} as never;
}

beforeEach(() => {
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "https://gateway.example");
});

afterEach(() => vi.unstubAllEnvs());

describe("GET /api/traces/export", () => {
	it.each(
		TRACE_EXPORT_PARAMS.filter(
			(entry) => entry.gatewayParam && entry.param !== "status",
		),
	)(
		"forwards registered export param $param as $gatewayParam",
		async ({ param, gatewayParam }) => {
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => "",
			});
			const value =
				(
					{
						sort: "duration",
						order: "asc",
						loop: "true",
						rescued: "retry",
						has_error: "true",
						issue: "truncated",
						failover: "true",
						cursor: "90:t2",
					} as Record<string, string>
				)[param] ?? "needle";
			await GET(req(new URLSearchParams({ [param]: value }).toString()));
			const url = new URL(fetchMock.mock.calls[0]?.[0] as string);
			if (!gatewayParam) throw new Error(`missing gateway param for ${param}`);
			expect(url.searchParams.get(gatewayParam)).toBe(value);
		},
	);
	it("exports the same search and failover view shown on the list", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () => "trace_id\n",
		});
		await GET(req("q=needle&failover=true&format=csv"));
		const params = new URL(fetchMock.mock.calls[0]?.[0] as string).searchParams;
		expect(params.get("q")).toBe("needle");
		expect(params.get("failover")).toBe("true");
	});
	it("mints the JWT, translates filters, forwards format, returns a CSV attachment", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () => "trace_id,model\nt1,gpt-4o\n",
			headers: new Headers({
				"x-tracelane-truncated": "true",
				"x-tracelane-row-count": "10000",
				"x-tracelane-next-cursor": "90:t2",
			}),
		});
		const res = await GET(
			req(
				"status=error&model=gpt-4o&range=24h&format=csv&sort=duration&order=asc&issue=truncated,filtered",
			),
		);
		expect(res.status).toBe(200);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toContain("https://gateway.example/v1/traces/export?");
		expect(url).toContain("format=csv");
		expect(url).toContain("model=gpt-4o");
		expect(url).toContain("has_error=true"); // status=error → has_error
		expect(url).toContain("since="); // range=24h → since present
		expect(url).toContain("sort=duration"); // active sort forwarded → CSV matches screen
		expect(url).toContain("order=asc");
		expect(new URL(url).searchParams.get("issue")).toBe("truncated,filtered");
		expect((init.headers as Record<string, string>).authorization).toBe(
			"Bearer wos_jwt_user_a",
		);
		expect(res.headers.get("content-disposition")).toContain(
			'attachment; filename="traces.csv"',
		);
		expect(res.headers.get("content-type")).toContain("text/csv");
		expect(res.headers.get("x-tracelane-truncated")).toBe("true");
		expect(res.headers.get("x-tracelane-row-count")).toBe("10000");
		expect(res.headers.get("x-tracelane-next-cursor")).toBe("90:t2");
		expect(await res.text()).toContain("t1,gpt-4o");
	});

	it("defaults to CSV and maps status=ok → has_error=false", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () => "",
		});
		await GET(req("status=ok"));
		const url = fetchMock.mock.calls[0]?.[0] as string;
		expect(url).toContain("format=csv");
		expect(url).toContain("has_error=false");
	});

	it("json format → application/json attachment", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () => "[]",
		});
		const res = await GET(req("format=json"));
		expect(res.headers.get("content-disposition")).toContain("traces.json");
		expect(res.headers.get("content-type")).toContain("application/json");
	});

	it("maps gateway 5xx → 502 and unreachable → 503", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 500,
			text: async () => "",
		});
		expect((await GET(req("format=csv"))).status).toBe(502);
		fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));
		expect((await GET(req("format=csv"))).status).toBe(503);
	});
});
