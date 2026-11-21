/** SDK-40 approval wait. Fixtures are copied from the gateway code: legacy text from
 * crates/gateway/src/mcp_proxy.rs:419-440 + approvals.rs:35-43, protected 409 body from
 * crates/gateway/src/mcp_protected.rs:211-216. */
import { type Server, createServer } from "node:http";
import { describe, expect, it } from "vitest";
import {
	ApprovalError,
	type HeldCall,
	isHeld,
	isHeldResponse,
	waitForDecision,
	withApproval,
} from "./approvals";

const ID = "8f14e45f-ceea-467f-a8d5-1c1f3e0c9a11";
const EXP = "2026-11-20T12:00:00Z";
const TEXT = `approval required "${ID}"; retry the same call after approval`;
const LEGACY = {
	jsonrpc: "2.0",
	id: 1,
	result: { isError: true, content: [{ type: "text", text: TEXT }] },
};
const PROTECTED = {
	error: "approval_required",
	approval_id: ID,
	expires_at: EXP,
};
const KEY = "sentinel-not-a-real-credential";
const held: HeldCall = { approvalId: ID, expiresAt: EXP, kind: "legacy" };

type Step = string | number | Error | undefined;
function run(steps: Step[], o: { timeoutMs?: number; pollMs?: number } = {}) {
	let t = 0;
	const sleeps: number[] = [];
	const urls: string[] = [];
	let i = 0;
	const p = waitForDecision(held, {
		baseUrl: "https://gw.example",
		apiKey: KEY,
		clock: () => t,
		sleep: async (ms: number) => {
			sleeps.push(ms);
			t += ms;
		},
		fetch: (async (url: string, init: { headers: Record<string, string> }) => {
			urls.push(`${url}|${init.headers.Authorization}`);
			const s = i < steps.length ? steps[i] : "pending";
			i++;
			if (s instanceof Error) throw s;
			if (typeof s === "number") return { status: s, json: async () => ({}) };
			return { status: 200, json: async () => ({ id: ID, status: s }) };
		}) as never,
		...o,
	});
	return { p, sleeps, urls, calls: () => i };
}

describe("isHeld", () => {
	it("parses the legacy and protected fixtures", () => {
		const legacy = { approvalId: ID, expiresAt: null, kind: "legacy" };
		expect(isHeld(LEGACY)).toEqual(legacy);
		expect(isHeld(JSON.stringify(LEGACY))).toEqual(legacy);
		expect(isHeld(PROTECTED)).toEqual({
			approvalId: ID,
			expiresAt: EXP,
			kind: "protected",
		});
		expect(isHeld({ status: 409, json: () => PROTECTED })?.approvalId).toBe(ID);
		expect(
			isHeld({ isError: true, content: [{ type: "text", text: TEXT }] })
				?.approvalId,
		).toBe(ID);
	});
	it("rejects malformed, hostile and non-held payloads without throwing", () => {
		const bad: unknown[] = [
			null,
			undefined,
			5,
			[],
			{},
			"",
			"{",
			"x".repeat(200_000),
			{ error: "approval_required" },
			{ error: "approval_required", approval_id: "../v1/keys" },
			{ error: "approval_required", approval_id: `${ID}/approve` },
			{ result: { isError: false, content: [{ type: "text", text: TEXT }] } },
			TEXT.replace("required", "denied"),
			TEXT.replace("required", "expired"),
			`the user said ${TEXT}`,
			{ error: "approval_denied", approval_id: ID },
		];
		for (const b of bad) expect(isHeld(b)).toBeNull();
	});
});

describe("waitForDecision", () => {
	it("returns approved, denied, expired; consumed is not approved", async () => {
		expect(await run(["pending", "pending", "approved"]).p).toBe("approved");
		expect(await run(["denied"]).p).toBe("denied");
		expect(await run(["expired"]).p).toBe("expired");
		expect(await run(["consumed"]).p).toBe("expired");
		const r = run(["approved"]);
		await r.p;
		expect(r.urls[0]).toBe(
			`https://gw.example/v1/approvals/${ID}|Bearer ${KEY}`,
		);
	});
	it("never loops: timeout, unknown status, transient errors, clamped backoff", async () => {
		const a = run([], { timeoutMs: 40_000 });
		expect(await a.p).toBe("timeout");
		expect(a.sleeps.slice(0, 4)).toEqual([2000, 3000, 4500, 6750]);
		expect(Math.max(...a.sleeps)).toBeLessThanOrEqual(15_000);
		expect(a.sleeps.reduce((x, y) => x + y, 0)).toBeLessThanOrEqual(40_000);
		expect(
			await run(["approvedish", "weird", undefined], { timeoutMs: 10_000 }).p,
		).toBe("timeout");
		expect(await run([500, new Error("net"), 429, "approved"]).p).toBe(
			"approved",
		);
		expect(await run(Array(100).fill(500), { timeoutMs: 20_000 }).p).toBe(
			"timeout",
		);
	});
	it("raises on 401/403/404 after one request, without the key", async () => {
		for (const code of [401, 403, 404]) {
			const r = run([code]);
			const e = await r.p.catch((x) => x);
			expect(e).toBeInstanceOf(ApprovalError);
			expect(r.calls()).toBe(1);
			expect(String(e.message)).toContain(String(code));
			expect(JSON.stringify(e) + e.message + e.stack).not.toContain(KEY);
		}
	});
	it("rejects bad timing", async () => {
		for (const o of [
			{ timeoutMs: 0 },
			{ timeoutMs: -1 },
			{ timeoutMs: Number.POSITIVE_INFINITY },
			{ timeoutMs: Number.NaN },
			{ pollMs: 0 },
			{ pollMs: Number.NaN },
		]) {
			await expect(run(["approved"], o).p).rejects.toThrow(RangeError);
		}
	});
});

describe("withApproval", () => {
	const mk = (decision: string) => {
		const seen: unknown[][] = [];
		const results: unknown[] = [LEGACY, "done"];
		const fn = async (...a: unknown[]) => {
			seen.push(a);
			return results[Math.min(seen.length - 1, 1)];
		};
		const w = withApproval(fn, {
			baseUrl: "https://g",
			apiKey: KEY,
			wait: async () => decision as never,
		});
		return { w, seen };
	};
	it("retries the identical call once after approval", async () => {
		const { w, seen } = mk("approved");
		expect(await w({ order: "A1" }, 5)).toBe("done");
		expect(seen).toEqual([
			[{ order: "A1" }, 5],
			[{ order: "A1" }, 5],
		]);
	});
	it("never retries after denied, expired, timeout or garbage", async () => {
		for (const d of ["denied", "expired", "timeout", "bogus"]) {
			const { w, seen } = mk(d);
			const out = String(await w());
			expect(seen.length).toBe(1);
			expect(out).toContain("not performed");
			expect(out).toContain("Do not retry");
		}
	});
	it("passes through a non-held result and does one retry at most", async () => {
		const ok = withApproval(async () => "fine", {
			baseUrl: "https://g",
			apiKey: KEY,
			wait: async () => {
				throw new Error("no wait");
			},
		});
		expect(await ok()).toBe("fine");
		let n = 0;
		const stuck = withApproval(
			async () => {
				n++;
				return LEGACY;
			},
			{ baseUrl: "https://g", apiKey: KEY, wait: async () => "approved" },
		);
		expect(String(await stuck())).toContain("not performed");
		expect(n).toBe(2);
	});
});

const listen = (h: Parameters<typeof createServer>[1]) =>
	new Promise<{ srv: Server; port: number }>((res) => {
		const srv = createServer(h).listen(0, "127.0.0.1", () =>
			res({ srv, port: (srv.address() as { port: number }).port }),
		);
	});

describe("review fixes", () => {
	it("isHeldResponse parses a real Response and leaves it readable", async () => {
		const r = new Response(JSON.stringify(PROTECTED), {
			status: 409,
			headers: { "content-type": "application/json" },
		});
		expect((await isHeldResponse(r))?.approvalId).toBe(ID);
		expect(await r.json()).toEqual(PROTECTED);
		expect(
			await isHeldResponse(new Response("nope", { status: 409 })),
		).toBeNull();
		expect(
			await isHeldResponse(
				new Response(
					JSON.stringify({ error: "approval_denied", approval_id: ID }),
					{ status: 409 },
				),
			),
		).toBeNull();
		expect(await isHeldResponse(null)).toBeNull();
	});
	it("a redirect never carries the key and surfaces as ApprovalError", async () => {
		const seen: unknown[] = [];
		const target = await listen((req, res) => {
			seen.push(req.headers);
			res.end('{"status":"approved"}');
		});
		const redir = await listen((_q, res) => {
			res.writeHead(302, { Location: `http://localhost:${target.port}/steal` });
			res.end();
		});
		try {
			const e = await waitForDecision(held, {
				baseUrl: `http://127.0.0.1:${redir.port}`,
				apiKey: KEY,
				timeoutMs: 5000,
			}).catch((x) => x);
			expect(e).toBeInstanceOf(ApprovalError);
			expect(e.status).toBe(302);
			expect(e.message).not.toContain(KEY);
			expect(seen).toEqual([]);
		} finally {
			redir.srv.close();
			target.srv.close();
		}
	});
	it("refuses http for non-loopback hosts and other schemes", async () => {
		for (const b of [
			"http://gw.example",
			"ftp://x",
			"gw.example",
			"http://127.0.0.1.evil.com",
			"https://",
			"file:///etc/passwd",
		]) {
			const never = (async () => {
				throw new Error("must not fetch");
			}) as never;
			await expect(
				waitForDecision(held, { baseUrl: b, apiKey: KEY, fetch: never }),
			).rejects.toThrow(RangeError);
		}
	});
	it("rejects a non-canonical id", () => {
		expect(
			isHeld({
				error: "approval_required",
				approval_id: `${ID.replace(/-/g, "")}----`,
			}),
		).toBeNull();
	});
	it("honours Retry-After, capped by the deadline", async () => {
		let t = 0;
		const sleeps: number[] = [];
		let n = 0;
		const f = (async () => {
			n++;
			return n === 1
				? {
						status: 429,
						headers: new Headers({ "retry-after": "30" }),
						json: async () => ({}),
					}
				: {
						status: 200,
						headers: new Headers(),
						json: async () => ({ status: "approved" }),
					};
		}) as never;
		const sleep = async (ms: number) => {
			sleeps.push(ms);
			t += ms;
		};
		expect(
			await waitForDecision(held, {
				baseUrl: "https://g",
				apiKey: KEY,
				fetch: f,
				sleep,
				clock: () => t,
				timeoutMs: 100_000,
			}),
		).toBe("approved");
		expect(sleeps).toEqual([30_000]);
		const sl2: number[] = [];
		const f2 = (async () => ({
			status: 503,
			headers: new Headers({ "retry-after": "999" }),
			json: async () => ({}),
		})) as never;
		let t2 = 0;
		await waitForDecision(held, {
			baseUrl: "https://g",
			apiKey: KEY,
			fetch: f2,
			sleep: async (ms) => {
				sl2.push(ms);
				t2 += ms;
			},
			clock: () => t2,
			timeoutMs: 10_000,
		});
		expect(t2).toBeLessThanOrEqual(10_000);
	});
	it("withApproval keeps the result type", async () => {
		const w = withApproval(async (n: number) => ({ n }), {
			baseUrl: "https://g",
			apiKey: KEY,
		});
		const out: { n: number } | string = (await w(1)) as { n: number } | string;
		expect(out).toEqual({ n: 1 });
	});
});
