/**
 * `OBS-48` — the shares proxy must preserve the upstream STATUS AND BODY.
 *
 * Same shape as `app/api/guardrails/tool-pins/[tool_name]/route.test.ts`: the
 * unit under test is the status/body mapping, not the transport, so
 * `gatewayGet`/`gatewayPost` are mocked. A 403 must read as "your role can't
 * do this" and a 409 (over the 10-active-links cap) must carry the gateway's
 * own message — collapsing either into a generic failure is the role-403
 * defect this repo has already paid for once.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const gatewayGet = vi.fn();
const gatewayPost = vi.fn();

class FakeGatewayError extends Error {
	status: number;
	body: Record<string, unknown> | null;
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

vi.mock("@/lib/gateway", () => ({
	gatewayGet: (path: string) => gatewayGet(path),
	gatewayPost: (path: string, body: unknown) => gatewayPost(path, body),
	GatewayError: FakeGatewayError,
}));

const { GET, POST } = await import("./route");

const params = (traceId: string) => ({ params: Promise.resolve({ traceId }) });

function postReq(body: unknown) {
	return new Request("http://localhost/api/traces/t1/shares", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
	}) as never;
}

describe("POST /api/traces/[traceId]/shares", () => {
	beforeEach(() => {
		gatewayGet.mockReset();
		gatewayPost.mockReset();
	});

	it("forwards a valid expiry to the gateway and returns its body", async () => {
		gatewayPost.mockResolvedValueOnce({
			id: "s1",
			token: "tok",
			url: "https://app.tracelane.dev/s/tok",
			expires_at: "2026-10-01T00:00:00Z",
		});
		const res = await POST(postReq({ expires_in_days: 7 }), params("t1"));
		expect(res.status).toBe(200);
		expect(gatewayPost).toHaveBeenCalledWith("/v1/traces/t1/share", {
			expires_in_days: 7,
		});
		expect(await res.json()).toEqual({
			id: "s1",
			token: "tok",
			url: "https://app.tracelane.dev/s/tok",
			expires_at: "2026-10-01T00:00:00Z",
		});
	});

	it("defaults to 30 days when no body is sent", async () => {
		gatewayPost.mockResolvedValueOnce({
			id: "s1",
			token: "tok",
			url: "u",
			expires_at: "x",
		});
		const req = new Request("http://localhost/api/traces/t1/shares", {
			method: "POST",
		}) as never;
		await POST(req, params("t1"));
		expect(gatewayPost).toHaveBeenCalledWith("/v1/traces/t1/share", {
			expires_in_days: 30,
		});
	});

	it("rejects an expiry outside {7,30,90} without calling the gateway", async () => {
		const res = await POST(postReq({ expires_in_days: 14 }), params("t1"));
		expect(res.status).toBe(400);
		expect(gatewayPost).not.toHaveBeenCalled();
	});

	it("keeps 403 distinguishable, body intact", async () => {
		gatewayPost.mockRejectedValueOnce(
			new FakeGatewayError(403, "forbidden", { error: "role_forbidden" }),
		);
		const res = await POST(postReq({ expires_in_days: 30 }), params("t1"));
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({ error: "role_forbidden" });
	});

	it("keeps 409 (over the 10-link cap) distinguishable, with the gateway's own message", async () => {
		gatewayPost.mockRejectedValueOnce(
			new FakeGatewayError(409, "too many", {
				error:
					"You have reached the maximum of 10 active links for this trace.",
			}),
		);
		const res = await POST(postReq({ expires_in_days: 30 }), params("t1"));
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({
			error: "You have reached the maximum of 10 active links for this trace.",
		});
	});

	it("keeps 404 (not this tenant's trace) distinguishable", async () => {
		gatewayPost.mockRejectedValueOnce(new FakeGatewayError(404, "not found"));
		const res = await POST(postReq({ expires_in_days: 30 }), params("t1"));
		expect(res.status).toBe(404);
	});
});

describe("GET /api/traces/[traceId]/shares", () => {
	beforeEach(() => {
		gatewayGet.mockReset();
	});

	it("forwards the list from the gateway", async () => {
		gatewayGet.mockResolvedValueOnce([
			{ id: "s1", created_at: "a", expires_at: "b", view_count: 3 },
		]);
		const req = new Request("http://localhost/api/traces/t1/shares") as never;
		const res = await GET(req, params("t1"));
		expect(res.status).toBe(200);
		expect(gatewayGet).toHaveBeenCalledWith("/v1/traces/t1/shares");
		expect(await res.json()).toEqual([
			{ id: "s1", created_at: "a", expires_at: "b", view_count: 3 },
		]);
	});

	it("passes an unmapped upstream status through rather than flattening it to 500", async () => {
		gatewayGet.mockRejectedValueOnce(
			new FakeGatewayError(503, "gateway unreachable"),
		);
		const req = new Request("http://localhost/api/traces/t1/shares") as never;
		const res = await GET(req, params("t1"));
		expect(res.status).toBe(503);
	});
});
