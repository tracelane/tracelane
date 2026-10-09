/**
 * Tests for lib/welcome-email.ts (PLT-52) — behind RESEND_API_KEY + RESEND_FROM,
 * fail-open, never throws, once per workspace.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
	buildWelcomeEmail,
	resetWelcomeEmailStateForTests,
	scheduleWelcomeEmail,
	sendWelcomeEmail,
} from "./welcome-email";

const INPUT = {
	workspaceId: "org_NEW",
	workspaceName: "Acme",
	to: "me@acme.co",
};

function setEnv(key: string | undefined, from: string | undefined) {
	if (key === undefined) Reflect.deleteProperty(process.env, "RESEND_API_KEY");
	else process.env.RESEND_API_KEY = key;
	if (from === undefined) Reflect.deleteProperty(process.env, "RESEND_FROM");
	else process.env.RESEND_FROM = from;
}

function resendOk(status = 200) {
	const spy = vi.fn(
		async () => ({ ok: status < 400, status }) as unknown as Response,
	);
	vi.stubGlobal("fetch", spy);
	return spy;
}

beforeEach(() => {
	resetWelcomeEmailStateForTests();
	setEnv("re_test_not_a_real_key", "Tracelane <hello@tracelane.dev>");
	vi.spyOn(console, "warn").mockImplementation(() => {});
	vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
	vi.unstubAllGlobals();
	setEnv(undefined, undefined);
});

describe("unconfigured — a logged no-op", () => {
	it("no API key: no fetch, exactly one log line, even across signups", async () => {
		setEnv(undefined, "Tracelane <hello@tracelane.dev>");
		const spy = resendOk();
		expect(await sendWelcomeEmail(INPUT)).toBe("skipped");
		expect(await sendWelcomeEmail({ ...INPUT, workspaceId: "org_TWO" })).toBe(
			"skipped",
		);
		expect(spy).not.toHaveBeenCalled();
		const warn = vi.mocked(console.warn);
		expect(warn).toHaveBeenCalledTimes(1);
		expect(JSON.parse(String(warn.mock.calls[0]?.[0]))).toEqual({
			event: "welcome_email_skipped",
			marker: "TRACELANE_DEGRADED email_unconfigured",
			reason: "RESEND_API_KEY unset",
		});
	});

	it("key set but RESEND_FROM unset: skipped too — no sender is invented", async () => {
		setEnv("re_test_not_a_real_key", undefined);
		const spy = resendOk();
		expect(await sendWelcomeEmail(INPUT)).toBe("skipped");
		expect(spy).not.toHaveBeenCalled();
		expect(String(vi.mocked(console.warn).mock.calls[0]?.[0])).toContain(
			"RESEND_FROM unset",
		);
	});

	it("a recipient that is not a single plain address is skipped, not sent", async () => {
		const spy = resendOk();
		for (const bad of ["a@b.co, evil@x.co", "no-at-sign", "a b@c.co", ""]) {
			expect(await sendWelcomeEmail({ ...INPUT, to: bad })).toBe("skipped");
		}
		expect(spy).not.toHaveBeenCalled();
	});
});

describe("configured — one correct POST", () => {
	it("posts once to Resend with the right headers and body; recipient = session email", async () => {
		const spy = resendOk();
		expect(await sendWelcomeEmail(INPUT)).toBe("sent");
		expect(spy).toHaveBeenCalledTimes(1);
		const [url, init] = spy.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://api.resend.com/emails");
		expect(init.method).toBe("POST");
		const headers = init.headers as Record<string, string>;
		expect(headers.authorization).toBe("Bearer re_test_not_a_real_key");
		expect(headers["content-type"]).toBe("application/json");
		expect(headers["idempotency-key"]).toBe("welcome-org_NEW");
		const body = JSON.parse(String(init.body)) as Record<string, unknown>;
		expect(body.to).toEqual(["me@acme.co"]);
		expect(body.from).toBe("Tracelane <hello@tracelane.dev>");
		expect(body.reply_to).toBe("founder@tracelane.dev");
		expect(body.subject).toBe("Your Tracelane workspace is ready");
		expect(String(body.text)).toContain("https://gateway.tracelane.dev/v1");
		expect(String(body.text)).toContain(
			"https://docs.tracelane.dev/quickstart",
		);
		expect(String(body.html)).toContain("<ol>");
		// Sent, so neither a skip nor a failure line.
		expect(console.warn).not.toHaveBeenCalled();
		expect(console.error).not.toHaveBeenCalled();
	});

	it("never logs the recipient address or the API key", async () => {
		resendOk(500);
		await sendWelcomeEmail(INPUT);
		const logged = JSON.stringify([
			vi.mocked(console.warn).mock.calls,
			vi.mocked(console.error).mock.calls,
		]);
		expect(logged).not.toContain("me@acme.co");
		expect(logged).not.toContain("re_test_not_a_real_key");
	});
});

describe("Resend failing never breaks the caller", () => {
	for (const status of [400, 403, 429, 500, 503]) {
		it(`HTTP ${status}: resolves "failed", no throw`, async () => {
			resendOk(status);
			await expect(sendWelcomeEmail(INPUT)).resolves.toBe("failed");
			expect(console.error).toHaveBeenCalled();
		});
	}

	it("fetch throws: resolves 'failed', no throw", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				throw new Error("network down");
			}),
		);
		await expect(sendWelcomeEmail(INPUT)).resolves.toBe("failed");
	});

	it("scheduleWelcomeEmail outside a request scope falls back and does not throw", async () => {
		const spy = resendOk();
		expect(() => scheduleWelcomeEmail(INPUT)).not.toThrow();
		await vi.waitFor(() => expect(spy).toHaveBeenCalledTimes(1));
	});
});

describe("once per workspace", () => {
	it("the same workspace twice sends once", async () => {
		const spy = resendOk();
		expect(await sendWelcomeEmail(INPUT)).toBe("sent");
		expect(await sendWelcomeEmail(INPUT)).toBe("duplicate");
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("a different workspace is its own send", async () => {
		const spy = resendOk();
		await sendWelcomeEmail(INPUT);
		await sendWelcomeEmail({ ...INPUT, workspaceId: "org_OTHER" });
		expect(spy).toHaveBeenCalledTimes(2);
	});
});

describe("copy", () => {
	it("never puts the (user-written) workspace name into the mail (security review M1)", () => {
		const hostile =
			'<script>alert("x")</script> Visit https://evil.example\nNew paragraph';
		const { html, text, subject } = buildWelcomeEmail(hostile);
		for (const part of [html, text, subject]) {
			expect(part).not.toContain("evil.example");
			expect(part).not.toContain("script");
			expect(part).not.toContain("New paragraph");
		}
		expect(text).toContain("Your workspace is ready.");
	});

	it("contains the three steps and none of the banned or unmeasured claims", () => {
		const { text } = buildWelcomeEmail(null);
		expect(text).toContain("Settings -> API Keys");
		expect(text).toContain("https://app.tracelane.dev/settings/api-keys");
		expect(text).toContain("https://app.tracelane.dev/traces");
		for (const banned of [
			/tamper-proof/i,
			/100%/,
			/sub-?\d+\s?ms/i,
			/\d+\s?(rps|k rps)/i,
			/before (they|the tool)/i,
			/block|prevent/i,
			/minutes?/i,
		]) {
			expect(text).not.toMatch(banned);
		}
	});
});
