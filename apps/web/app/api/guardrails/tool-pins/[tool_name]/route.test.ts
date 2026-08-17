/**
 * GWY-15b — the unpin proxy must preserve the upstream STATUS.
 *
 * The defect this guards against is not "does it call the gateway" but "does the
 * caller learn WHY it failed". A proxy that collapses every non-ok upstream into
 * one message turns an owner-only 403 into a generic failure, which is how a
 * permissions problem gets mistaken for an outage. Each case below asserts a
 * distinct, actionable outcome.
 *
 * `gatewayDelete` is mocked because the real one needs a WorkOS session; the unit
 * under test is the status mapping, not the transport.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const gatewayDelete = vi.fn();

class FakeGatewayError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

vi.mock("@/lib/gateway", () => ({
	gatewayDelete: (path: string) => gatewayDelete(path),
	GatewayError: FakeGatewayError,
}));

const { DELETE } = await import("./route");

const params = (tool_name: string) => ({
	params: Promise.resolve({ tool_name }),
});
const req = new Request("http://localhost/api/guardrails/tool-pins/x", {
	method: "DELETE",
});

describe("DELETE /api/guardrails/tool-pins/[tool_name]", () => {
	beforeEach(() => {
		gatewayDelete.mockReset();
	});

	it("returns 204 with no body on success", async () => {
		gatewayDelete.mockResolvedValueOnce(undefined);
		const res = await DELETE(req, params("search_web"));
		expect(res.status).toBe(204);
		expect(await res.text()).toBe("");
	});

	it("forwards the tool name URL-ENCODED so it cannot rewrite the upstream path", async () => {
		gatewayDelete.mockResolvedValueOnce(undefined);
		await DELETE(req, params("evil/../../v1/keys"));
		expect(gatewayDelete).toHaveBeenCalledWith(
			"/v1/guardrails/tool-pins/evil%2F..%2F..%2Fv1%2Fkeys",
		);
	});

	it("keeps 403 distinguishable — not an outage, a permissions problem", async () => {
		gatewayDelete.mockRejectedValueOnce(new FakeGatewayError(403, "forbidden"));
		const res = await DELETE(req, params("search_web"));
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({
			error: "role_forbidden",
			required_role: "owner",
		});
	});

	it("keeps 404 distinguishable — the pin is already gone", async () => {
		gatewayDelete.mockRejectedValueOnce(
			new FakeGatewayError(404, "no such pin"),
		);
		const res = await DELETE(req, params("search_web"));
		expect(res.status).toBe(404);
		expect(await res.json()).toEqual({ error: "no_such_pin" });
	});

	it("passes an unmapped upstream status through rather than flattening it to 500", async () => {
		gatewayDelete.mockRejectedValueOnce(
			new FakeGatewayError(503, "unreachable"),
		);
		const res = await DELETE(req, params("search_web"));
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({ error: "upstream_error", status: 503 });
	});

	it("rejects an empty tool name without calling the gateway", async () => {
		const res = await DELETE(req, params(""));
		expect(res.status).toBe(400);
		expect(gatewayDelete).not.toHaveBeenCalled();
	});

	it("rejects a name over the gateway's 256-byte bound without calling it", async () => {
		const res = await DELETE(req, params("a".repeat(257)));
		expect(res.status).toBe(400);
		expect(gatewayDelete).not.toHaveBeenCalled();
	});
});
