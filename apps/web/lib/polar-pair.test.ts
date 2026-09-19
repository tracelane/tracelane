/**
 * BILL-02 §2.5 — the ONE pairing implementation shared by the Polar webhook
 * (synchronous, on the Worker) and `scripts/ops/polar-reconcile-annual.ts`
 * (on demand). Every assertion here is about what it asks POLAR to do and in
 * what ORDER — the order is the B7 stage 1 finding (O5): the card must be the
 * customer's default BEFORE the usage subscription exists, or its first
 * invoice goes past_due and the period's credits are withheld.
 */

import { describe, expect, it } from "vitest";
import {
	POLAR_API_BASE,
	type PolarClient,
	makePolarClient,
	pairUsageSubscription,
	polarApiBase,
} from "./polar-pair";

type Call = { method: string; path: string; body?: unknown };

function fakePolar(opts: {
	cards?: { id: string; type: string }[];
	postFails?: string;
	methodsFail?: string;
	sessionFails?: string;
	portalPatchFails?: string;
}) {
	const calls: Call[] = [];
	const client: PolarClient = {
		get: async (path) => {
			calls.push({ method: "GET", path });
			if (opts.methodsFail) throw new Error(opts.methodsFail);
			return { items: opts.cards ?? [{ id: "pm_card_1", type: "card" }] };
		},
		post: async (path, body) => {
			calls.push({ method: "POST", path, body });
			if (path === "/v1/customer-sessions/") {
				if (opts.sessionFails) throw new Error(opts.sessionFails);
				return { token: "polar_cst_test_session" };
			}
			if (opts.postFails) throw new Error(opts.postFails);
			return { id: "sub_usage_new", status: "active" };
		},
		patch: async (path, body) => {
			calls.push({ method: "PATCH", path, body });
			return {};
		},
		patchAs: async (bearer, path, body) => {
			calls.push({ method: `PATCH as ${bearer}`, path, body });
			if (opts.portalPatchFails) throw new Error(opts.portalPatchFails);
			return { default_payment_method_id: "pm_card_1" };
		},
	};
	return { client, calls };
}

describe("pairUsageSubscription — the pairing calls, in the order Polar needs", () => {
	// B-435 (falsified on the sandbox 2026-09-19, customer 9ea70888…): the
	// org-token `PATCH /v1/customers/{id} {default_payment_method_id}` answers
	// 200 and IGNORES the field (`CustomerUpdate` has no such property; the
	// read-back stayed null). The only path Polar honours is the customer
	// PORTAL API under a customer-session token: `POST /v1/customer-sessions/`
	// then `PATCH /v1/customer-portal/customers/me` (read-back = the card id).
	it("apply: payment-methods → customer SESSION → portal PATCH default (as the customer) → POST usage subscription; returns the new id", async () => {
		const { client, calls } = fakePolar({});
		const r = await pairUsageSubscription({
			polar: client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: true,
		});
		expect(r).toEqual({
			ok: true,
			applied: true,
			usageSubscriptionId: "sub_usage_new",
			defaultPaymentMethodId: "pm_card_1",
		});
		expect(calls).toEqual([
			{ method: "GET", path: "/v1/customers/cust_1/payment-methods" },
			{
				method: "POST",
				path: "/v1/customer-sessions/",
				body: { customer_id: "cust_1" },
			},
			{
				method: "PATCH as polar_cst_test_session",
				path: "/v1/customer-portal/customers/me",
				body: { default_payment_method_id: "pm_card_1" },
			},
			{
				method: "POST",
				path: "/v1/subscriptions/",
				body: { product_id: "prod_team_v1_usage_month", customer_id: "cust_1" },
			},
		]);
	});

	it("B-435: the org-token PATCH /v1/customers/{id} is NEVER used for the default card (Polar ignores it)", async () => {
		const { client, calls } = fakePolar({});
		await pairUsageSubscription({
			polar: client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: true,
		});
		expect(
			calls.filter(
				(c) => c.method === "PATCH" && c.path.startsWith("/v1/customers/"),
			),
		).toEqual([]);
	});

	it("the session or the portal PATCH fails → the usage subscription is STILL created (allowances still land) and the result says the default was NOT set, with the reason", async () => {
		const a = fakePolar({
			sessionFails:
				"Polar POST /v1/customer-sessions/ -> 403: <body withheld: may echo the token>",
		});
		const ra = await pairUsageSubscription({
			polar: a.client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: true,
		});
		expect(ra.ok && ra.applied && ra.usageSubscriptionId).toBe("sub_usage_new");
		expect(ra.ok && ra.defaultPaymentMethodId).toBeNull();
		expect(ra.ok && ra.applied && ra.defaultCardError).toContain(
			"customer-sessions",
		);
		expect(a.calls.map((c) => c.method)).toEqual(["GET", "POST", "POST"]);

		const b = fakePolar({
			portalPatchFails:
				"Polar PATCH /v1/customer-portal/customers/me -> 422: bad id",
		});
		const rb = await pairUsageSubscription({
			polar: b.client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: true,
		});
		expect(rb.ok && rb.applied && rb.usageSubscriptionId).toBe("sub_usage_new");
		expect(rb.ok && rb.defaultPaymentMethodId).toBeNull();
		expect(rb.ok && rb.applied && rb.defaultCardError).toContain(
			"customer-portal",
		);
	});

	it("dry run (apply=false): reads the payment methods and touches NOTHING — the reconciler's --check", async () => {
		const { client, calls } = fakePolar({});
		const r = await pairUsageSubscription({
			polar: client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: false,
		});
		expect(r).toEqual({
			ok: true,
			applied: false,
			usageSubscriptionId: null,
			defaultPaymentMethodId: "pm_card_1",
		});
		expect(calls.map((c) => c.method)).toEqual(["GET"]);
	});

	it("no card on file: no session, no portal PATCH, the POST still happens (the reconciler's behaviour, unchanged) and the result says the default was not set", async () => {
		const { client, calls } = fakePolar({ cards: [] });
		const r = await pairUsageSubscription({
			polar: client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: true,
		});
		expect(r.ok).toBe(true);
		expect(r.ok && r.defaultPaymentMethodId).toBeNull();
		expect(calls.map((c) => c.method)).toEqual(["GET", "POST"]);
	});

	it("Polar refuses the POST (402/422/5xx) → ok:false with Polar's reason, nothing thrown", async () => {
		const { client } = fakePolar({
			postFails: "Polar POST /v1/subscriptions/ -> 422: no payment method",
		});
		const r = await pairUsageSubscription({
			polar: client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: true,
		});
		expect(r).toEqual({
			ok: false,
			reason: "Polar POST /v1/subscriptions/ -> 422: no payment method",
			defaultPaymentMethodId: "pm_card_1",
		});
	});

	it("the payment-methods read itself fails → ok:false, and no write was attempted", async () => {
		const { client, calls } = fakePolar({ methodsFail: "network down" });
		const r = await pairUsageSubscription({
			polar: client,
			customerId: "cust_1",
			usageProductId: "prod_team_v1_usage_month",
			apply: true,
		});
		expect(r.ok).toBe(false);
		expect(calls.map((c) => c.method)).toEqual(["GET"]);
	});

	it("apply with no usage product id configured → ok:false before any write (never POST an empty product_id)", async () => {
		const { client, calls } = fakePolar({});
		const r = await pairUsageSubscription({
			polar: client,
			customerId: "cust_1",
			usageProductId: null,
			apply: true,
		});
		expect(r.ok).toBe(false);
		expect(r.ok === false && r.reason).toMatch(/usage product/i);
		expect(calls.filter((c) => c.method !== "GET")).toEqual([]);
	});
});

describe("makePolarClient — the fetch-backed client both callers share", () => {
	it("sends the bearer token, JSON body, and throws on a non-2xx with the status and body text", async () => {
		const seen: { url: string; init: RequestInit }[] = [];
		const fetchImpl = (async (
			url: string | URL | Request,
			init?: RequestInit,
		) => {
			seen.push({ url: String(url), init: init ?? {} });
			if (String(url).endsWith("/v1/subscriptions/")) {
				return new Response('{"detail":"nope"}', { status: 422 });
			}
			return new Response('{"items":[]}', { status: 200 });
		}) as unknown as typeof fetch;
		const client = makePolarClient({
			token: "polar_oat_test",
			apiBase: POLAR_API_BASE.sandbox,
			fetchImpl,
		});
		await client.get("/v1/customers/c/payment-methods");
		expect(seen[0]?.url).toBe(
			"https://sandbox-api.polar.sh/v1/customers/c/payment-methods",
		);
		const headers = seen[0]?.init.headers as Record<string, string>;
		expect(headers.authorization).toBe("Bearer polar_oat_test");
		await expect(
			client.post("/v1/subscriptions/", { product_id: "p" }),
		).rejects.toThrow(
			'Polar POST /v1/subscriptions/ -> 422: {"detail":"nope"}',
		);
		expect(seen[1]?.init.body).toBe('{"product_id":"p"}');
	});

	it("a 401/403 body is WITHHELD from the thrown reason (it can echo the Bearer token — billing.md ban)", async () => {
		const fetchImpl = (async () =>
			new Response('{"detail":"invalid token polar_oat_SECRET"}', {
				status: 401,
			})) as unknown as typeof fetch;
		const client = makePolarClient({
			token: "polar_oat_SECRET",
			apiBase: POLAR_API_BASE.production,
			fetchImpl,
		});
		let message = "";
		try {
			await client.get("/v1/subscriptions/");
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).toContain("401");
		expect(message).not.toContain("polar_oat_SECRET");
	});

	it("honours an AbortSignal: a hung Polar rejects when the deadline fires instead of hanging the caller", async () => {
		const fetchImpl = ((_url: unknown, init?: RequestInit) =>
			new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () =>
					reject(init.signal?.reason ?? new Error("aborted")),
				);
			})) as unknown as typeof fetch;
		const client = makePolarClient({
			token: "t",
			apiBase: POLAR_API_BASE.production,
			fetchImpl,
			signal: AbortSignal.timeout(30),
		});
		const started = Date.now();
		await expect(client.get("/v1/subscriptions/")).rejects.toThrow();
		expect(Date.now() - started).toBeLessThan(2_000);
	});

	it("polarApiBase picks sandbox only when asked — the same rule as the reconciler's --sandbox flag", () => {
		expect(polarApiBase(false)).toBe("https://api.polar.sh");
		expect(polarApiBase(true)).toBe("https://sandbox-api.polar.sh");
	});
});
