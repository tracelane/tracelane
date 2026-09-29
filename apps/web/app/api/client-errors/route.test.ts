/** The crash beacon trusts nothing and always answers 204; only a well-formed report writes a line. */
import type { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { POST } from "./route";

const req = (body: string, ip = "203.0.113.7") =>
	({
		text: async () => body,
		headers: new Headers({ "user-agent": "UA/1", "cf-connecting-ip": ip }),
	}) as unknown as NextRequest;

afterEach(() => vi.restoreAllMocks());

describe("POST /api/client-errors", () => {
	it("writes ONE tagged line with only known fields, truncated", async () => {
		const log = vi.spyOn(console, "error").mockImplementation(() => {});
		const res = await POST(
			req(
				JSON.stringify({
					kind: "boundary",
					message: "x".repeat(900),
					path: "/traces",
					evil: "drop me",
				}),
			),
		);
		expect(res.status).toBe(204);
		expect(log).toHaveBeenCalledTimes(1);
		const line = JSON.parse(String(log.mock.calls[0]?.[0]));
		expect(line.tl).toBe("client-error");
		expect(line.kind).toBe("boundary");
		expect(line.message).toHaveLength(500);
		expect(line.evil).toBeUndefined();
		expect(line.ua).toBe("UA/1");
	});

	it("an unknown kind is recorded as unknown", async () => {
		const log = vi.spyOn(console, "error").mockImplementation(() => {});
		await POST(req(JSON.stringify({ kind: "<script>", message: "m" })));
		expect(JSON.parse(String(log.mock.calls[0]?.[0])).kind).toBe("unknown");
	});

	it("oversized, empty or non-JSON bodies write nothing and still answer 204", async () => {
		const log = vi.spyOn(console, "error").mockImplementation(() => {});
		for (const b of ["", "not json", "x".repeat(9000)]) {
			expect((await POST(req(b))).status).toBe(204);
		}
		expect(log).not.toHaveBeenCalled();
	});

	it("caps one client at 30 reports a minute and still answers 204 (security review 2026-09-27)", async () => {
		const log = vi.spyOn(console, "error").mockImplementation(() => {});
		const body = JSON.stringify({ kind: "window", message: "loop" });
		for (let n = 0; n < 45; n++) {
			const res = await POST(req(body, "198.51.100.9"));
			expect(res.status).toBe(204);
		}
		expect(log).toHaveBeenCalledTimes(30);
		await POST(req(body, "198.51.100.10"));
		expect(log).toHaveBeenCalledTimes(31);
	});

	it("never logs a query string — it can carry ids or tokens", async () => {
		const log = vi.spyOn(console, "error").mockImplementation(() => {});
		await POST(
			req(
				JSON.stringify({
					kind: "window",
					message: "m",
					path: "/traces?token=abc&x=1",
				}),
				"192.0.2.44",
			),
		);
		expect(JSON.parse(String(log.mock.calls[0]?.[0])).path).toBe("/traces");
	});
});
