/**
 * Tests for lib/signup-alert.ts (PLT-53): one plain notice to the operator per new
 * workspace, fail-open, never throws, never sent to the signer-up.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const rl = vi.hoisted(() => ({ rateLimit: vi.fn() }));
vi.mock("@/lib/rate-limit", () => ({ rateLimit: rl.rateLimit }));

import {
	buildSignupAlert,
	resetSignupAlertStateForTests,
	sanitizeUserText,
	sendSignupAlert,
} from "./signup-alert";

const INPUT = {
	workspaceId: "org_NEW",
	workspaceName: "Acme",
	tenantId: "6f1c2a4e-0000-4000-8000-000000000001",
	email: "me@acme.co",
	emailVerified: true,
	at: new Date("2026-11-15T10:20:30.000Z"),
};

function setEnv(vars: Record<string, string | undefined>) {
	for (const [k, v] of Object.entries(vars)) {
		if (v === undefined) Reflect.deleteProperty(process.env, k);
		else process.env[k] = v;
	}
}

function resend(status = 200) {
	const spy = vi.fn(
		async (..._args: unknown[]) =>
			({ ok: status < 400, status }) as unknown as Response,
	);
	vi.stubGlobal("fetch", spy);
	return spy;
}

function body(spy: ReturnType<typeof resend>) {
	const init = spy.mock.calls[0]?.[1] as RequestInit;
	return {
		json: JSON.parse(String(init.body)),
		headers: init.headers as Record<string, string>,
	};
}

beforeEach(() => {
	resetSignupAlertStateForTests();
	rl.rateLimit.mockReset().mockResolvedValue(true);
	setEnv({
		RESEND_API_KEY: "re_test_not_a_real_key",
		RESEND_FROM: "Tracelane <hello@tracelane.dev>",
		SIGNUP_ALERT_TO: undefined,
	});
	vi.spyOn(console, "warn").mockImplementation(() => {});
	vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
	vi.unstubAllGlobals();
	setEnv({
		RESEND_API_KEY: undefined,
		RESEND_FROM: undefined,
		SIGNUP_ALERT_TO: undefined,
	});
});

describe("sendSignupAlert", () => {
	it("sends one notice to the operator, never to the signer-up", async () => {
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("sent");
		const { json, headers } = body(spy);
		expect(json.to).toEqual(["founder@tracelane.dev"]);
		expect(json.to).not.toContain(INPUT.email);
		expect(headers["idempotency-key"]).toBe("signup-alert-org_NEW");
		expect(json.text).toContain("me@acme.co");
		expect(json.text).toContain("Nov 15, 2026 · 10:20 UTC");
		expect(json.text).toContain("2026-11-15T10:20:30.000Z");
	});

	it("honours SIGNUP_ALERT_TO", async () => {
		setEnv({ SIGNUP_ALERT_TO: "ops@tracelane.dev" });
		const spy = resend();
		await sendSignupAlert(INPUT);
		expect(body(spy).json.to).toEqual(["ops@tracelane.dev"]);
	});

	it("refuses a configured recipient that is not one plain address", async () => {
		setEnv({ SIGNUP_ALERT_TO: "a@x.co, b@y.co" });
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("skipped");
		expect(spy).not.toHaveBeenCalled();
	});

	it("states an unverified email instead of dropping the notice", async () => {
		const spy = resend();
		await sendSignupAlert({ ...INPUT, emailVerified: false });
		expect(body(spy).json.text).toContain("email verified: no");
	});

	it("is a no-op without Resend configuration", async () => {
		setEnv({ RESEND_API_KEY: undefined });
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("skipped");
		expect(spy).not.toHaveBeenCalled();
	});

	it("sends once per workspace in an isolate", async () => {
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("sent");
		expect(await sendSignupAlert(INPUT)).toBe("duplicate");
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("returns failed on a Resend 500 without throwing", async () => {
		resend(500);
		expect(await sendSignupAlert(INPUT)).toBe("failed");
	});

	it("returns failed on a network throw without throwing", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				throw new Error("network");
			}),
		);
		expect(await sendSignupAlert(INPUT)).toBe("failed");
	});

	it("is a no-op without RESEND_FROM", async () => {
		setEnv({ RESEND_FROM: undefined });
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("skipped");
		expect(spy).not.toHaveBeenCalled();
	});

	it("sends from RESEND_FROM", async () => {
		const spy = resend();
		await sendSignupAlert(INPUT);
		expect(body(spy).json.from).toBe("Tracelane <hello@tracelane.dev>");
	});

	it("keys the provider dedupe per workspace", async () => {
		const spy = resend();
		await sendSignupAlert(INPUT);
		await sendSignupAlert({ ...INPUT, workspaceId: "org_OTHER" });
		const keys = spy.mock.calls.map(
			(c) =>
				(c[1] as { headers: Record<string, string> }).headers[
					"idempotency-key"
				],
		);
		expect(keys).toEqual(["signup-alert-org_NEW", "signup-alert-org_OTHER"]);
	});
});

describe("buildSignupAlert", () => {
	it("carries the workspace name and both ids in text and HTML", () => {
		const { text, html } = buildSignupAlert(INPUT);
		for (const part of [text, html]) {
			expect(part).toContain("Acme");
			expect(part).toContain("org_NEW");
			expect(part).toContain(INPUT.tenantId);
		}
	});

	it("labels an unnamed workspace", () => {
		expect(buildSignupAlert({ ...INPUT, workspaceName: null }).text).toContain(
			"workspace name (user-supplied): (unnamed)",
		);
	});

	it("labels the time in UTC and ISO", () => {
		const { text } = buildSignupAlert(INPUT);
		expect(text).toContain(
			"signed up: Nov 15, 2026 · 10:20 UTC (2026-11-15T10:20:30.000Z)",
		);
	});

	it("escapes user text in the HTML part", () => {
		const { html, text } = buildSignupAlert({
			...INPUT,
			workspaceName: '<a href="https://evil.example">x</a>',
			email: "a<b>@acme.co",
		});
		expect(html).not.toContain("<a href");
		expect(html).toContain("&lt;a href=");
		expect(html).toContain("a&lt;b&gt;@acme.co");
		expect(text).toContain('<a href="https://evil.example">x</a>');
	});

	it("keeps the subject free of user text", () => {
		const { subject } = buildSignupAlert({
			...INPUT,
			workspaceName: "Free money\r\nBcc: x@y",
		});
		expect(subject).toBe("New Tracelane signup");
	});
});

describe("signup alert — hostile workspace name (review M1)", () => {
	it("CRLF in the name cannot forge an extra row in the text part", () => {
		const { text } = buildSignupAlert({
			...INPUT,
			workspaceName: "Acme\r\nemail verified: yes\r\ntenant id: forged",
		});
		expect(text).not.toMatch(/\r/);
		expect(
			text.split("\n").filter((l) => l.startsWith("tenant id:")),
		).toHaveLength(1);
		expect(
			text.split("\n").filter((l) => l.startsWith("email verified:")),
		).toHaveLength(1);
	});
	it("strips bidi overrides and zero-width characters", () => {
		const out = sanitizeUserText("a\u202Egnp.exe\u200Bb\u2028c");
		expect(out).not.toMatch(/[\u202E\u200B\u2028]/);
		expect(out).toBe("a gnp.exe b c");
	});
	it("caps a 10 KB name at 100 characters plus an ellipsis", () => {
		const { text } = buildSignupAlert({
			...INPUT,
			workspaceName: "x".repeat(10_000),
		});
		const line = text
			.split("\n")
			.find((l) => l.startsWith("workspace name (user-supplied):"));
		expect(line).toBe(`workspace name (user-supplied): ${"x".repeat(100)}…`);
	});
	it("puts the user-supplied name last and labels it", () => {
		const rows = buildSignupAlert(INPUT)
			.text.split("\n")
			.filter((l) => l.includes(": "));
		expect(rows.at(-1)).toBe("workspace name (user-supplied): Acme");
	});
	it("HTML part still escapes the sanitised name", () => {
		const { html } = buildSignupAlert({
			...INPUT,
			workspaceName: "<img src=x onerror=1>",
		});
		expect(html).not.toContain("<img");
		expect(html).toContain("&lt;img");
	});
});

describe("signup alert — global hourly cap (review M2)", () => {
	it("sends while under the cap, keyed globally", async () => {
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("sent");
		expect(rl.rateLimit).toHaveBeenCalledWith(
			"signup-alert:global",
			50,
			3_600_000,
		);
		expect(spy).toHaveBeenCalledTimes(1);
	});
	it("skips without sending when the cap is reached", async () => {
		rl.rateLimit.mockResolvedValue(false);
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("skipped");
		expect(spy).not.toHaveBeenCalled();
	});
	it("skips without sending when the counter is unavailable", async () => {
		rl.rateLimit.mockRejectedValue(new Error("rate_limit_unavailable"));
		const spy = resend();
		expect(await sendSignupAlert(INPUT)).toBe("skipped");
		expect(spy).not.toHaveBeenCalled();
	});
});

describe("signup alert — cap visibility (review L2)", () => {
	it("marks only the first cap hit per isolate as degraded", async () => {
		rl.rateLimit.mockResolvedValue(false);
		const warn = vi.mocked(console.warn);
		await sendSignupAlert({ ...INPUT, workspaceId: "org_A" });
		await sendSignupAlert({ ...INPUT, workspaceId: "org_B" });
		const capped = warn.mock.calls
			.map((c) => JSON.parse(String(c[0])))
			.filter((e) => e.event === "signup_alert_capped");
		expect(capped).toHaveLength(2);
		expect(capped[0].marker).toBe("TRACELANE_DEGRADED signup_alert_capped");
		expect(capped[1].marker).toBeUndefined();
	});
});
