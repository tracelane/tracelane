/**
 * Tests for lib/email.ts — behind RESEND_API_KEY, fail-open, never throws.
 * Negative cases (unset key, provider failure) first per `.claude/rules/testing.md`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_KEY = process.env.RESEND_API_KEY;

describe("sendEmail — RESEND_API_KEY unset", () => {
	beforeEach(() => {
		vi.resetModules();
		Reflect.deleteProperty(process.env, "RESEND_API_KEY");
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		if (ORIGINAL_KEY === undefined)
			Reflect.deleteProperty(process.env, "RESEND_API_KEY");
		else process.env.RESEND_API_KEY = ORIGINAL_KEY;
	});

	it("logs the TRACELANE_DEGRADED marker exactly ONCE per process, never throws", async () => {
		const { sendEmail } = await import("./email");
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const first = await sendEmail({
			to: "a@b.co",
			subject: "s",
			html: "<p>h</p>",
			text: "t",
		});
		const second = await sendEmail({
			to: "a@b.co",
			subject: "s",
			html: "<p>h</p>",
			text: "t",
		});

		expect(first).toBe(false);
		expect(second).toBe(false);
		expect(fetchSpy).not.toHaveBeenCalled();
		const marker = warnSpy.mock.calls.filter((c) =>
			String(c[0]).includes("TRACELANE_DEGRADED email_unconfigured"),
		);
		expect(marker).toHaveLength(1); // ONE warn per process, not per call
		warnSpy.mockRestore();
	});
});

describe("sendEmail — RESEND_API_KEY set", () => {
	beforeEach(() => {
		vi.resetModules();
		process.env.RESEND_API_KEY = "re_test_do_not_use_in_prod";
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		if (ORIGINAL_KEY === undefined)
			Reflect.deleteProperty(process.env, "RESEND_API_KEY");
		else process.env.RESEND_API_KEY = ORIGINAL_KEY;
	});

	it("REJECT: a non-2xx Resend response returns false, never throws, never logs the body", async () => {
		const { sendEmail } = await import("./email");
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					({
						ok: false,
						status: 422,
						json: async () => ({ message: "SECRET" }),
					}) as unknown as Response,
			),
		);
		const ok = await sendEmail({
			to: "a@b.co",
			subject: "s",
			html: "<p>h</p>",
			text: "t",
		});
		expect(ok).toBe(false);
		expect(
			errSpy.mock.calls.some((c) => String(c[1] ?? c[0]).includes("SECRET")),
		).toBe(false);
		errSpy.mockRestore();
	});

	it("REJECT: a network error returns false, never throws", async () => {
		const { sendEmail } = await import("./email");
		vi.spyOn(console, "error").mockImplementation(() => {});
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				throw new Error("ECONNREFUSED");
			}),
		);
		await expect(
			sendEmail({ to: "a@b.co", subject: "s", html: "<p>h</p>", text: "t" }),
		).resolves.toBe(false);
	});

	it("HAPPY: posts to Resend with the Bearer key and the exact request body", async () => {
		const { sendEmail } = await import("./email");
		const spy = vi.fn(
			async (..._args: unknown[]) =>
				({
					ok: true,
					json: async () => ({ id: "email_1" }),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		const ok = await sendEmail({
			to: "a@b.co",
			subject: "Hi",
			html: "<p>hi</p>",
			text: "hi",
		});
		expect(ok).toBe(true);
		const [url, init] = spy.mock.calls[0] as unknown as [
			string,
			{ headers: Record<string, string>; body: string },
		];
		expect(url).toBe("https://api.resend.com/emails");
		expect(init.headers.authorization).toBe(
			"Bearer re_test_do_not_use_in_prod",
		);
		const body = JSON.parse(init.body) as { to: string[]; subject: string };
		expect(body.to).toEqual(["a@b.co"]);
		expect(body.subject).toBe("Hi");
	});

	it("HAPPY: the three billing templates render the right subject + plan names", async () => {
		const {
			sendDunningStartedEmail,
			sendDroppedToFreeEmail,
			sendPlanChangedEmail,
		} = await import("./email");
		const spy = vi.fn(
			async (..._args: unknown[]) =>
				({ ok: true, json: async () => ({ id: "x" }) }) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);

		await sendDunningStartedEmail("a@b.co", {
			plan: "team",
			retryDays: [1, 5, 14],
		});
		const dunningCall = spy.mock.calls[0] as unknown as [
			string,
			{ body: string },
		];
		const dunningBody = JSON.parse(dunningCall[1].body) as {
			html: string;
			subject: string;
		};
		expect(dunningBody.subject).toContain("could not process");
		expect(dunningBody.html).toContain("Team");
		expect(dunningBody.html).toContain("1, 5, 14");

		await sendDroppedToFreeEmail("a@b.co", {
			previousPlan: "business",
			dataHoldUntil: new Date("2026-10-13T00:00:00Z"),
		});
		const dropCall = spy.mock.calls[1] as unknown as [string, { body: string }];
		const dropBody = JSON.parse(dropCall[1].body) as { html: string };
		expect(dropBody.html).toContain("Business");
		expect(dropBody.html).toContain("2026-10-13");

		await sendPlanChangedEmail("a@b.co", {
			fromPlan: "builder",
			toPlan: "team",
		});
		const changeCall = spy.mock.calls[2] as unknown as [
			string,
			{ body: string },
		];
		const changeBody = JSON.parse(changeCall[1].body) as {
			subject: string;
			html: string;
		};
		expect(changeBody.subject).toContain("Team");
		expect(changeBody.html).toContain("Builder");
	});
});
