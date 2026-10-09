import type { NextRequest } from "next/server";
import { expect, it, vi } from "vitest";
const gatewayGet = vi.hoisted(() =>
	vi.fn(async (_path: string) => ({ traces: [] })),
);
const calls: Array<{ cacheKey: string }> = [];
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: async () => ({ tenantId: "workspace" }),
}));
vi.mock("@/lib/gateway", () => ({
	gatewayGet,
	forwardParams: (source: URLSearchParams, keys: string[]) =>
		new URLSearchParams([...source].filter(([key]) => keys.includes(key))),
}));
vi.mock("@/lib/query-deadline", () => ({
	streamQueryWithDeadline: (
		read: () => Promise<unknown>,
		options: { cacheKey: string },
	) => {
		calls.push(options);
		return new ReadableStream({
			async start(controller) {
				await read();
				controller.close();
			},
		});
	},
}));
import { GET } from "./route";
it("live tail uses the same loop and rescue filters and isolates their cache entries", async () => {
	for (const rescued of ["any", "failover", "retry"]) {
		const response = await GET({
			nextUrl: new URL(
				`http://local/api/traces/stream?loop=true&rescued=${rescued}`,
			),
		} as NextRequest);
		await response.text();
		const target = new URL(
			gatewayGet.mock.calls.at(-1)?.[0] as string,
			"http://gateway",
		);
		expect(target.pathname).toBe("/v1/traces");
		expect(target.searchParams.get("loop")).toBe("true");
		expect(target.searchParams.get("rescued")).toBe(rescued);
	}
	expect(new Set(calls.map((c) => c.cacheKey)).size).toBe(3);
});

it("live tail sends a retry of at least 15000 ms before closing", async () => {
	const response = await GET({
		nextUrl: new URL("http://local/api/traces/stream"),
	} as NextRequest);
	const body = await response.text();
	const retry = /^retry:\s*(\d+)$/m.exec(body);
	expect(retry).not.toBeNull();
	expect(Number(retry?.[1])).toBeGreaterThanOrEqual(15000);
});
