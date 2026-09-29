/**
 * GWY-27 — /api/settings/model-aliases proxy. The gateway owns validation and the
 * owner gate; this route must forward the token, never put a tenant in the body,
 * pass the gateway's OWN typed refusal codes through (the form shows them at the
 * field), and mask everything else. Negative cases first (`.claude/rules/testing.md`).
 */
import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ token: "wos_access_token_xyz" }));
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: "org_TEST",
	})),
}));
vi.mock("@/lib/gateway", () => ({ gatewayBaseUrl: () => "http://gw.test" }));

import { DELETE, GET, PUT } from "./route";

const fetchMock = vi.fn();
beforeEach(() => {
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
});

const putReq = (body: unknown) =>
	({ json: async () => body }) as unknown as NextRequest;
const delReq = (qs: string) =>
	({
		nextUrl: new URL(`http://app.test/api/settings/model-aliases${qs}`),
	}) as unknown as NextRequest;
const upstream = (status: number, body?: unknown) =>
	({
		status,
		ok: status >= 200 && status < 300,
		json: async () => body,
	}) as unknown as Response;

describe("PUT", () => {
	it("refuses a blank alias or target with 400 and never calls the gateway", async () => {
		expect(
			(await PUT(putReq({ alias: " ", target_model: "gpt-5" }))).status,
		).toBe(400);
		expect((await PUT(putReq({ alias: "fast" }))).status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("forwards the token and a body with NO tenant, create defaulting to false", async () => {
		fetchMock.mockResolvedValue(
			upstream(200, {
				alias: "fast",
				target_model: "gpt-5",
				provider: "openai",
			}),
		);
		const res = await PUT(
			putReq({ alias: " fast ", target_model: "gpt-5", tenant_id: "evil" }),
		);
		expect(res.status).toBe(200);
		const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("http://gw.test/v1/model-aliases");
		expect((opts.headers as Record<string, string>).authorization).toBe(
			`Bearer ${h.token}`,
		);
		expect(JSON.parse(opts.body as string)).toEqual({
			alias: "fast",
			target_model: "gpt-5",
			create: false,
		});
	});

	it("passes the gateway's typed refusal through so the form can show it", async () => {
		fetchMock.mockResolvedValue(
			upstream(400, {
				error: "unroutable_target",
				message: "`x` does not route",
			}),
		);
		const res = await PUT(
			putReq({ alias: "fast", target_model: "x", create: true }),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("unroutable_target");
	});

	it("renders the owner gate as the typed 403, and masks a 5xx as 502", async () => {
		fetchMock.mockResolvedValueOnce(upstream(403, { required_role: "owner" }));
		const forbidden = await PUT(
			putReq({ alias: "fast", target_model: "gpt-5" }),
		);
		expect(forbidden.status).toBe(403);
		expect(await forbidden.json()).toEqual({
			error: "role_forbidden",
			required_role: "owner",
		});

		fetchMock.mockResolvedValueOnce(
			upstream(500, { error: "secret internal detail" }),
		);
		const broken = await PUT(putReq({ alias: "fast", target_model: "gpt-5" }));
		expect(broken.status).toBe(502);
		expect(JSON.stringify(await broken.json())).not.toContain(
			"secret internal detail",
		);
	});
});

describe("GET / DELETE", () => {
	it("relays the list", async () => {
		const list = { items: [], max: 50, can_edit: true };
		fetchMock.mockResolvedValue(upstream(200, list));
		expect(await (await GET()).json()).toEqual(list);
	});

	it("DELETE needs ?alias=, encodes it, and relays a 204", async () => {
		expect((await DELETE(delReq(""))).status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
		fetchMock.mockResolvedValue(upstream(204));
		const res = await DELETE(delReq("?alias=team%2Ffast"));
		expect(res.status).toBe(204);
		expect(fetchMock.mock.calls[0]?.[0]).toBe(
			"http://gw.test/v1/model-aliases?alias=team%2Ffast",
		);
	});
});
