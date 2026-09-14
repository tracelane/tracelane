/**
 * `OBS-48` — DELETE /api/traces/[traceId]/shares/[id] revoke proxy.
 * Same status/body-preservation contract as the sibling `shares/route.test.ts`.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const gatewayDelete = vi.fn();

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
	gatewayDelete: (path: string) => gatewayDelete(path),
	GatewayError: FakeGatewayError,
}));

const { DELETE } = await import("./route");

const params = (traceId: string, id: string) => ({
	params: Promise.resolve({ traceId, id }),
});
const req = new Request("http://localhost/api/traces/t1/shares/s1", {
	method: "DELETE",
}) as never;

describe("DELETE /api/traces/[traceId]/shares/[id]", () => {
	beforeEach(() => {
		gatewayDelete.mockReset();
	});

	it("returns 204 with no body on success", async () => {
		gatewayDelete.mockResolvedValueOnce(undefined);
		const res = await DELETE(req, params("t1", "s1"));
		expect(res.status).toBe(204);
		expect(await res.text()).toBe("");
		expect(gatewayDelete).toHaveBeenCalledWith("/v1/traces/t1/shares/s1");
	});

	it("URL-encodes both path segments so neither can rewrite the upstream path", async () => {
		gatewayDelete.mockResolvedValueOnce(undefined);
		await DELETE(req, params("evil/../v1/keys", "also/evil"));
		expect(gatewayDelete).toHaveBeenCalledWith(
			"/v1/traces/evil%2F..%2Fv1%2Fkeys/shares/also%2Fevil",
		);
	});

	it("keeps 404 distinguishable — not yours or already gone", async () => {
		gatewayDelete.mockRejectedValueOnce(
			new FakeGatewayError(404, "no such share", { error: "not_found" }),
		);
		const res = await DELETE(req, params("t1", "s1"));
		expect(res.status).toBe(404);
		expect(await res.json()).toEqual({ error: "not_found" });
	});

	it("keeps 403 distinguishable", async () => {
		gatewayDelete.mockRejectedValueOnce(
			new FakeGatewayError(403, "forbidden", { error: "role_forbidden" }),
		);
		const res = await DELETE(req, params("t1", "s1"));
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({ error: "role_forbidden" });
	});
});
