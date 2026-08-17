/**
 * SET-26 — self-serve email change.
 *
 * The end state under test: a signed-in user can move their own account to a
 * new address, and after doing so **WorkOS holds the new address**, the address
 * is marked unverified, a verification mail is requested for it, and the
 * Postgres mirror agrees. Anything short of WorkOS positively showing the new
 * address is a failure, not a success — so the "must reject" cases below are the
 * bulk of this file, and each asserts that NOTHING was written on the way out.
 *
 * Negative cases first (`.claude/rules/testing.md`). No network: `fetch` is
 * stubbed and every outbound call is inspected.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	session: {
		tenantId: "org_S",
		userId: "user_ME",
		email: "old@example.com",
		role: "owner" as string | null,
	},
	db: null as DbMock | null,
	recordAdminAction: vi.fn(async (_e: unknown) => undefined),
	/** Attempt counter so each test gets a fresh rate-limit key. */
	n: 0,
}));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));
vi.mock("@/lib/auth", () => ({ requireSession: vi.fn(async () => h.session) }));
vi.mock("@/lib/admin-audit", () => ({
	recordAdminAction: h.recordAdminAction,
	ipFromRequest: () => "203.0.113.9",
}));

import { POST } from "./route";
import { validateEmailChange } from "./validate";

const GOOD = {
	newEmail: "new@example.com",
	confirmEmail: "new@example.com",
	confirmCurrentEmail: "old@example.com",
};

/** Build a request. Each call uses a distinct user id so the per-user rate
 * limiter (module-level state) never bleeds between cases. */
function req(body: unknown): NextRequest {
	h.n += 1;
	h.session = { ...h.session, userId: `user_ME_${h.n}` };
	return {
		json: async () => body,
		headers: new Headers({ "user-agent": "vitest" }),
	} as unknown as NextRequest;
}

interface WorkosStub {
	/** Status for the PUT. */
	putStatus?: number;
	/** Body the PUT returns (the "updated" user). */
	putBody?: unknown;
	/** Error text for a non-ok PUT. */
	putError?: string;
	/** Status for the verification-send POST. */
	sendOk?: boolean;
}

function stubWorkos(cfg: WorkosStub = {}) {
	const {
		putStatus = 200,
		putBody = { id: "user_ME", email: "new@example.com" },
		putError = "",
		sendOk = true,
	} = cfg;
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = String(args[0]);
		if (url.includes("/email_verification/send")) {
			return { ok: sendOk, status: sendOk ? 200 : 500 } as unknown as Response;
		}
		return {
			ok: putStatus >= 200 && putStatus < 300,
			status: putStatus,
			json: async () => putBody,
			text: async () => putError,
		} as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

const putCall = (spy: ReturnType<typeof stubWorkos>) =>
	spy.mock.calls.find(
		(c) => (c[1] as { method?: string } | undefined)?.method === "PUT",
	);
const putPayload = (spy: ReturnType<typeof stubWorkos>) =>
	JSON.parse(
		((putCall(spy)?.[1] as { body?: string } | undefined)?.body ??
			"{}") as string,
	) as Record<string, unknown>;
const sentVerification = (spy: ReturnType<typeof stubWorkos>) =>
	spy.mock.calls.some((c) => String(c[0]).includes("/email_verification/send"));

beforeEach(() => {
	h.session = {
		tenantId: "org_S",
		userId: "user_ME",
		email: "old@example.com",
		role: "owner",
	};
	// Per successful POST: [ mirror update, tenant select ]. Queued three deep so
	// a test that posts more than once doesn't run the queue dry mid-assertion.
	const tenantRow = [{ id: "11111111-1111-1111-1111-111111111111" }];
	h.db = makeDbMock([[], tenantRow, [], tenantRow, [], tenantRow]);
	// `vi.stubEnv` + `unstubAllEnvs` rather than assignment: a bare
	// `process.env.X = undefined` writes the STRING "undefined", which is truthy
	// and would leave the "no key configured" case untestable.
	vi.stubEnv("WORKOS_API_KEY", "sk_test_workos_do_not_use");
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// MUST REJECT
// ---------------------------------------------------------------------------

describe("SET-26 — refuses anything that is not a proved, deliberate change", () => {
	it("refuses when the current-address confirmation is wrong — a stolen cookie is not enough", async () => {
		const spy = stubWorkos();
		const res = await POST(
			req({ ...GOOD, confirmCurrentEmail: "someone-else@example.com" }),
		);
		expect(res.status).toBe(422);
		expect((await res.json()).error).toBe("current_email_mismatch");
		expect(putCall(spy)).toBeUndefined(); // nothing reached WorkOS
	});

	it("refuses when the two new-address fields differ — a typo is a lockout", async () => {
		const spy = stubWorkos();
		const res = await POST(req({ ...GOOD, confirmEmail: "nwe@example.com" }));
		expect(res.status).toBe(422);
		expect((await res.json()).error).toBe("confirmation_mismatch");
		expect(putCall(spy)).toBeUndefined();
	});

	it("refuses a no-op so it cannot silently un-verify the address in place", async () => {
		const spy = stubWorkos();
		const res = await POST(
			req({
				newEmail: "old@example.com",
				confirmEmail: "old@example.com",
				confirmCurrentEmail: "old@example.com",
			}),
		);
		expect(res.status).toBe(422);
		expect((await res.json()).error).toBe("email_unchanged");
		expect(putCall(spy)).toBeUndefined();
	});

	it("refuses a malformed address", async () => {
		const spy = stubWorkos();
		for (const bad of [
			"not-an-email",
			"no@tld",
			"two@@example.com",
			"spaces in@example.com",
			"@example.com",
			'"quoted"@example.com',
			"trailing@example.com.",
		]) {
			const res = await POST(
				req({
					newEmail: bad,
					confirmEmail: bad,
					confirmCurrentEmail: "old@example.com",
				}),
			);
			expect(res.status, bad).toBe(422);
			expect((await res.json()).error, bad).toBe("email_invalid");
		}
		expect(putCall(spy)).toBeUndefined();
	});

	it("refuses an over-long address before it reaches the provider", async () => {
		const spy = stubWorkos();
		const long = `${"a".repeat(250)}@example.com`;
		const res = await POST(
			req({
				newEmail: long,
				confirmEmail: long,
				confirmCurrentEmail: "old@example.com",
			}),
		);
		expect(res.status).toBe(422);
		expect((await res.json()).error).toBe("email_too_long");
		expect(putCall(spy)).toBeUndefined();
	});

	it("refuses a body that is not an object", async () => {
		stubWorkos();
		const res = await POST(req("just a string"));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_json");
	});

	it("reports an address already in use as a conflict, not a generic failure", async () => {
		stubWorkos({
			putStatus: 422,
			putError: JSON.stringify({ code: "email_not_available" }),
		});
		const res = await POST(req(GOOD));
		expect(res.status).toBe(409);
		expect((await res.json()).error).toBe("email_not_available");
	});

	it("is not configured away silently — no WorkOS key is a loud 501", async () => {
		vi.stubEnv("WORKOS_API_KEY", "");
		stubWorkos();
		const res = await POST(req(GOOD));
		expect(res.status).toBe(501);
	});

	it("caps repeated attempts per user", async () => {
		stubWorkos();
		// Pin ONE user id so every attempt shares a rate-limit key.
		h.session = { ...h.session, userId: "user_BURST" };
		const fixed = () =>
			({
				json: async () => ({
					...GOOD,
					confirmCurrentEmail: "wrong@example.com",
				}),
				headers: new Headers(),
			}) as unknown as NextRequest;
		const codes: number[] = [];
		for (let i = 0; i < 7; i++) codes.push((await POST(fixed())).status);
		expect(codes.filter((c) => c === 429).length).toBeGreaterThan(0);
	});
});

describe("SET-26 — a 200 from the provider is not proof the address moved", () => {
	it("fails when WorkOS 200s but the returned user still carries the OLD address", async () => {
		const spy = stubWorkos({
			putStatus: 200,
			putBody: { id: "user_ME", email: "old@example.com" },
		});
		const res = await POST(req(GOOD));
		expect(res.status).toBe(502);
		expect((await res.json()).error).toBe("workos_email_unchanged");
		// and nothing downstream ran on the strength of a false success
		expect(sentVerification(spy)).toBe(false);
		expect(h.recordAdminAction).not.toHaveBeenCalled();
		expect(h.db?.db.update).not.toHaveBeenCalled();
	});

	it("fails when WorkOS 200s with no email field at all", async () => {
		stubWorkos({ putStatus: 200, putBody: { id: "user_ME" } });
		const res = await POST(req(GOOD));
		expect(res.status).toBe(502);
		expect((await res.json()).error).toBe("workos_email_unchanged");
		expect(h.db?.db.update).not.toHaveBeenCalled();
	});

	it("fails closed when the provider is unreachable", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				throw new Error("ECONNREFUSED");
			}),
		);
		const res = await POST(req(GOOD));
		expect(res.status).toBe(502);
		expect((await res.json()).error).toBe("workos_unreachable");
		expect(h.db?.db.update).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// MUST ACCEPT — what the user can now do
// ---------------------------------------------------------------------------

describe("SET-26 — the address actually moves", () => {
	it("puts the new address on the WorkOS user and marks it unverified", async () => {
		const spy = stubWorkos();
		const res = await POST(req(GOOD));
		expect(res.status).toBe(200);

		const payload = putPayload(spy);
		expect(payload.email).toBe("new@example.com");
		// The new address is NOT trusted until the user proves they receive mail
		// there. Without this the handler would hand out a verified address on
		// nothing but a typed confirmation.
		expect(payload.email_verified).toBe(false);

		// targeted at the SESSION's user — never an id from the body
		expect(String(putCall(spy)?.[0])).toContain("user_ME");
	});

	it("requests the verification mail for the new address", async () => {
		const spy = stubWorkos();
		await POST(req(GOOD));
		expect(sentVerification(spy)).toBe(true);
		expect((await (await POST(req(GOOD))).json()).verificationSent).toBe(true);
	});

	it("tells the caller the session must be refreshed", async () => {
		stubWorkos();
		const body = await (await POST(req(GOOD))).json();
		expect(body.email).toBe("new@example.com");
		expect(body.reauthRequired).toBe(true);
	});

	it("normalises case so the mirror and the provider cannot disagree", async () => {
		const spy = stubWorkos({
			putBody: { id: "user_ME", email: "NEW@Example.com" },
		});
		const res = await POST(
			req({
				newEmail: "NEW@Example.com",
				confirmEmail: "new@example.COM",
				confirmCurrentEmail: "OLD@example.com",
			}),
		);
		expect(res.status).toBe(200);
		expect(putPayload(spy).email).toBe("new@example.com");
		expect((await res.json()).email).toBe("new@example.com");
	});

	it("mirrors the change into Postgres and records it as a security event", async () => {
		stubWorkos();
		await POST(req(GOOD));
		expect(h.db?.db.update).toHaveBeenCalled();
		expect(h.recordAdminAction).toHaveBeenCalledWith(
			expect.objectContaining({
				action: "account.email.change",
				targetId: expect.stringContaining("user_ME"),
				beforeJson: { email: "old@example.com" },
				afterJson: { email: "new@example.com", email_verified: false },
			}),
		);
	});

	it("still reports success when the mirror write fails — WorkOS is the record", async () => {
		stubWorkos();
		if (h.db)
			h.db.db.update.mockImplementation(() => {
				throw new Error("neon down");
			});
		const res = await POST(req(GOOD));
		expect(res.status).toBe(200);
		expect((await res.json()).email).toBe("new@example.com");
	});

	it("still reports success when the verification mail cannot be sent", async () => {
		stubWorkos({ sendOk: false });
		const res = await POST(req(GOOD));
		expect(res.status).toBe(200);
		expect((await res.json()).verificationSent).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// The validator, directly — the client shares it, so its verdicts must match.
// ---------------------------------------------------------------------------

describe("SET-26 — validator verdicts", () => {
	it("accepts a well-formed change", () => {
		const v = validateEmailChange(GOOD, "old@example.com");
		expect(v.ok).toBe(true);
		if (v.ok) expect(v.value.newEmail).toBe("new@example.com");
	});

	it("ignores surrounding whitespace on every field", () => {
		const v = validateEmailChange(
			{
				newEmail: "  new@example.com ",
				confirmEmail: "new@example.com  ",
				confirmCurrentEmail: " old@example.com ",
			},
			"old@example.com",
		);
		expect(v.ok).toBe(true);
	});

	it("never accepts a body whose fields are the wrong type", () => {
		for (const bad of [
			{ newEmail: 42 },
			{ newEmail: null },
			{ newEmail: ["new@example.com"] },
			{},
			null,
			[],
		]) {
			expect(validateEmailChange(bad, "old@example.com").ok).toBe(false);
		}
	});
});
