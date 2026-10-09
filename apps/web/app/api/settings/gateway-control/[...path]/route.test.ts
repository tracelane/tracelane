/**
 * OG-60 — the control relay. The refusals are asserted as the page receives them:
 * status AND the typed fields, with everything else dropped.
 */
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	token: vi.fn(async () => ({ token: "t" })),
	gw: vi.fn(),
}));
vi.mock("@/lib/auth", () => ({ requireGatewayToken: h.token }));
vi.mock("@/lib/gateway", () => ({ gatewayResponse: h.gw }));

import { DELETE, GET, POST, PUT } from "./route";

const ctx = (path: string) => ({
	params: Promise.resolve({ path: path.split("/") }),
});
const req = (
	method: string,
	path: string,
	init: { body?: string; headers?: Record<string, string>; qs?: string } = {},
) =>
	new NextRequest(
		`http://app.test/api/settings/gateway-control/${path}${init.qs ?? ""}`,
		{ method, body: init.body, headers: init.headers },
	);
/** What our own pages send on a state-changing call. */
const ours = {
	"sec-fetch-site": "same-origin",
	"content-type": "application/json",
};
const upstream = (status: number, body?: unknown, headers: HeadersInit = {}) =>
	new Response(body === undefined ? null : JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});

beforeEach(() => {
	h.token.mockClear();
	h.gw.mockReset();
});

describe("what the relay refuses before touching the gateway", () => {
	it("a route that is not listed is 404 and mints no token", async () => {
		const res = await GET(req("GET", "keys"), ctx("keys"));
		expect(res.status).toBe(404);
		expect(h.token).not.toHaveBeenCalled();
		expect(h.gw).not.toHaveBeenCalled();
	});

	it("a cross-site state change is refused; same-origin passes", async () => {
		const bad = await POST(
			req("POST", "controls/pause", {
				body: "{}",
				headers: { "sec-fetch-site": "cross-site" },
			}),
			ctx("controls/pause"),
		);
		expect(bad.status).toBe(403);
		expect(await bad.json()).toEqual({ error: "cross_site" });
		expect(h.gw).not.toHaveBeenCalled();

		h.gw.mockResolvedValue(upstream(200, { paused: true }));
		const ok = await POST(
			req("POST", "controls/pause", { body: "{}", headers: ours }),
			ctx("controls/pause"),
		);
		expect(ok.status).toBe(200);
	});

	it("a decoded ?/# in a wildcard segment is 404 and reaches nothing (L1)", async () => {
		for (const seg of ["p1?x=1", "p1#f", "p1%3Fx"]) {
			const res = await GET(req("GET", "projects/p1"), {
				params: Promise.resolve({ path: ["projects", seg] }),
			});
			expect(res.status, seg).toBe(404);
		}
		expect(h.token).not.toHaveBeenCalled();
		expect(h.gw).not.toHaveBeenCalled();
	});

	// L2 (security review, 2026-10-05): CSRF rested on Sec-Fetch-Site alone and let a
	// request WITHOUT it through. An unsafe method now needs Sec-Fetch-Site same-origin
	// or an Origin equal to the app's, and a body must be declared application/json.
	it("an unsafe call with neither Sec-Fetch-Site nor a matching Origin is 403", async () => {
		for (const headers of <Record<string, string>[]>[
			{},
			{ origin: "http://evil.test" },
			{ origin: "null" },
			{ "sec-fetch-site": "same-site" },
			{ "sec-fetch-site": "none", origin: "http://evil.test" },
		]) {
			const res = await POST(
				req("POST", "controls/pause", {
					body: "{}",
					headers: { "content-type": "application/json", ...headers },
				}),
				ctx("controls/pause"),
			);
			expect(res.status, JSON.stringify(headers)).toBe(403);
			expect(await res.json()).toEqual({ error: "cross_site" });
		}
		const del = await DELETE(req("DELETE", "projects/p1"), ctx("projects/p1"));
		expect(del.status).toBe(403);
		expect(h.token).not.toHaveBeenCalled();
		expect(h.gw).not.toHaveBeenCalled();
	});

	it("a matching Origin passes without Sec-Fetch-Site (L2)", async () => {
		h.gw.mockResolvedValue(upstream(200, { paused: true }));
		const ok = await POST(
			req("POST", "controls/pause", {
				body: "{}",
				headers: {
					origin: "http://app.test",
					"content-type": "application/json",
				},
			}),
			ctx("controls/pause"),
		);
		expect(ok.status).toBe(200);
	});

	it("a body not declared application/json is 415 (L2)", async () => {
		for (const ct of [
			undefined,
			"text/plain",
			"application/x-www-form-urlencoded",
		]) {
			const res = await PUT(
				req("PUT", "controls/policy", {
					body: '{"policy":null}',
					headers: {
						"sec-fetch-site": "same-origin",
						...(ct ? { "content-type": ct } : {}),
					},
				}),
				ctx("controls/policy"),
			);
			expect(res.status, String(ct)).toBe(415);
		}
		expect(h.gw).not.toHaveBeenCalled();
	});

	it("a body that is not a JSON object is 400", async () => {
		for (const body of ["[1]", "not json", "null", '"x"']) {
			const res = await PUT(
				req("PUT", "controls/policy", { body, headers: ours }),
				ctx("controls/policy"),
			);
			expect(res.status, body).toBe(400);
		}
		expect(h.gw).not.toHaveBeenCalled();
	});
});

describe("forwarding", () => {
	it("sends the verb, path and query with the user's body", async () => {
		h.gw.mockResolvedValue(upstream(200, { items: [] }));
		await GET(
			req("GET", "audit/control-changes", {
				qs: "?limit=50&action=workspace.pause",
			}),
			ctx("audit/control-changes"),
		);
		expect(h.gw).toHaveBeenCalledWith(
			"/v1/audit/control-changes?limit=50&action=workspace.pause",
			{ method: "GET" },
		);
		h.gw.mockResolvedValue(upstream(200, {}));
		await PUT(
			req("PUT", "controls/policy", { body: '{"policy":null}', headers: ours }),
			ctx("controls/policy"),
		);
		const [path, init] = h.gw.mock.calls[1] as [string, RequestInit];
		expect(path).toBe("/v1/controls/policy");
		expect(init.method).toBe("PUT");
		expect(init.body).toBe('{"policy":null}');
	});

	it("an empty POST body goes as {} (pause with no reason)", async () => {
		h.gw.mockResolvedValue(upstream(200, {}));
		await POST(
			req("POST", "controls/resume", {
				headers: { "sec-fetch-site": "same-origin" },
			}),
			ctx("controls/resume"),
		);
		expect((h.gw.mock.calls[0] as [string, RequestInit])[1].body).toBe("{}");
	});

	it("204 stays 204 with no body", async () => {
		h.gw.mockResolvedValue(new Response(null, { status: 204 }));
		const res = await DELETE(
			req("DELETE", "projects/p1", {
				headers: { "sec-fetch-site": "same-origin" },
			}),
			ctx("projects/p1"),
		);
		expect(res.status).toBe(204);
		expect(await res.text()).toBe("");
	});
});

describe("typed refusals reach the page; nothing else does", () => {
	it("keeps a role 403's required_role and drops unknown fields", async () => {
		h.gw.mockResolvedValue(
			upstream(403, {
				error: "role_forbidden",
				required_role: "admin",
				capability: "manage_controls",
				upgrade_url: null,
				internal: "never",
			}),
		);
		const res = await POST(
			req("POST", "controls/pause", { body: "{}", headers: ours }),
			ctx("controls/pause"),
		);
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({
			error: "role_forbidden",
			required_role: "admin",
			capability: "manage_controls",
		});
	});

	it("keeps the lock-out 409's address and reason", async () => {
		h.gw.mockResolvedValue(
			upstream(409, {
				error: "would_lock_you_out",
				reason: "ip",
				message: "this allowlist does not include the address…",
				your_ip: "203.0.113.9",
				your_ip_attested: true,
			}),
		);
		const res = await PUT(
			req("PUT", "security/admin-access", { body: "{}", headers: ours }),
			ctx("security/admin-access"),
		);
		expect(res.status).toBe(409);
		expect(await res.json()).toMatchObject({
			error: "would_lock_you_out",
			reason: "ip",
			your_ip: "203.0.113.9",
			your_ip_attested: true,
		});
	});

	it("passes 423 and carries Retry-After on a 429", async () => {
		h.gw.mockResolvedValue(upstream(423, { error: "workspace_paused" }));
		expect((await GET(req("GET", "controls"), ctx("controls"))).status).toBe(
			423,
		);
		h.gw.mockResolvedValue(
			upstream(
				429,
				{ error: "control_rate_limited", retry_after_secs: 4 },
				{ "retry-after": "4" },
			),
		);
		const res = await PUT(
			req("PUT", "controls/blocks", { body: "{}", headers: ours }),
			ctx("controls/blocks"),
		);
		expect(res.status).toBe(429);
		expect(res.headers.get("retry-after")).toBe("4");
	});

	it("masks a gateway 500 and an unreachable gateway as 502", async () => {
		h.gw.mockResolvedValue(upstream(500, { error: "db password is hunter2" }));
		const res = await GET(req("GET", "controls"), ctx("controls"));
		expect(res.status).toBe(502);
		expect(JSON.stringify(await res.json())).not.toMatch(/hunter2/);
		h.gw.mockResolvedValue(upstream(502, { code: "gateway_unreachable" }));
		expect((await GET(req("GET", "controls"), ctx("controls"))).status).toBe(
			502,
		);
	});

	it("a 503 keeps its code (control_change_unavailable)", async () => {
		h.gw.mockResolvedValue(
			upstream(503, { error: "control_change_unavailable", message: "retry" }),
		);
		const res = await PUT(
			req("PUT", "controls/policy", { body: '{"policy":null}', headers: ours }),
			ctx("controls/policy"),
		);
		expect(res.status).toBe(503);
		expect(await res.json()).toMatchObject({
			error: "control_change_unavailable",
		});
	});
});
