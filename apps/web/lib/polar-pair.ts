/**
 * BILL-02 §2.5 — the annual PAIRING step, ONE implementation shared by:
 *
 *   - the Polar webhook on the Cloudflare Worker (`app/api/webhooks/polar/route.ts`),
 *     which runs it SYNCHRONOUSLY on the base's `active` event when
 *     `POLAR_WORKER_TOKEN` is set (O4, founder ruling 2026-09-19: the P2
 *     half-state lasted 51 s in sandbox stage 1 and "the reconciler's cadence"
 *     in prod — "do not accept it");
 *   - `scripts/ops/polar-reconcile-annual.ts`, which runs it on demand for a
 *     tenant Polar shows in P2.
 *
 * The calls, in THIS order (B7 stage 1, O5 — observed in the sandbox
 * 2026-09-16): the base checkout SAVES the customer's card but does not make it
 * the DEFAULT, and a subscription created by API has nothing else to charge —
 * its first non-zero usage invoice went `past_due` at once and the period's
 * credits were withheld until it was paid. So:
 *
 *   1. GET   /v1/customers/{id}/payment-methods           → the saved card
 *   2. POST  /v1/customer-sessions/ {customer_id}         → a customer-session token
 *   3. PATCH /v1/customer-portal/customers/me {default_payment_method_id}
 *            AS THE CUSTOMER (the session token as Bearer)  (2+3 skipped when no card)
 *   4. POST  /v1/subscriptions/ {product_id: <plan>_v1_usage_month, customer_id}
 *
 * B-435 — why 2+3 and not `PATCH /v1/customers/{id}` (what this did until
 * 2026-09-19, and what the reconciler recorded as its stage-1 "fix"): the
 * org-token customer PATCH answers 200 and IGNORES `default_payment_method_id`
 * — `CustomerUpdate` in Polar's OpenAPI (2026-04) has no such property, and the
 * falsification on the sandbox (customer `9ea70888…`, a real 4242 checkout)
 * read `null` back after it. Only `CustomerPortalCustomerUpdate` carries the
 * field, under a customer session; the same falsification read the card id
 * back after that call. A 200 that changes nothing is the silent-fallback
 * class in someone else's API.
 *
 * Scopes the token needs (read from https://docs.polar.sh/openapi.json,
 * version 2026-04, on 2026-09-19): `customers:read` or `customers:write` for
 * 1; `customer_sessions:write` for 2 (3 runs under the session, no org scope);
 * `subscriptions:write` for 4 and the `GET /v1/subscriptions/` list the
 * webhook uses to check for an existing usage half. Nothing else.
 *
 * THIS FILE HAS NO IMPORTS ON PURPOSE. The node script imports it by relative
 * path with a `.ts` extension (`--experimental-strip-types` needs one) while
 * the Worker's tsconfig (`moduleResolution: bundler`, no
 * `allowImportingTsExtensions`) refuses that spelling — so anything shared by
 * both must be self-contained. The plan/lookup-key classification lives in
 * `./polar-webhook.ts` and is reached by each caller on its own side.
 *
 * Pure over an injected client: the falsification IS the test suite
 * (`polar-pair.test.ts`); nothing here reads env or touches Neon. It never
 * throws for a Polar refusal — the caller decides what a failure means (the
 * webhook stays P2 and acks; the reconciler exits non-zero).
 */

export type PolarClient = {
	get: (path: string) => Promise<unknown>;
	post: (path: string, body: unknown) => Promise<unknown>;
	patch: (path: string, body: unknown) => Promise<unknown>;
	/** The same PATCH under a DIFFERENT Bearer — the customer-portal API takes a
	 *  customer-session token, never the organisation token. */
	patchAs: (bearer: string, path: string, body: unknown) => Promise<unknown>;
};

export const POLAR_API_BASE = {
	production: "https://api.polar.sh",
	sandbox: "https://sandbox-api.polar.sh",
} as const;

/** The reconciler's `--sandbox` flag and the Worker's `POLAR_SANDBOX=1` pick the same host. */
export function polarApiBase(sandbox: boolean): string {
	return sandbox ? POLAR_API_BASE.sandbox : POLAR_API_BASE.production;
}

/**
 * A fetch-backed Polar client. `signal` is the caller's DEADLINE for every call
 * made through this client (the webhook passes `AbortSignal.timeout(...)` so a
 * hung Polar cannot make the webhook miss Polar's own 10 s delivery timeout);
 * the reconciler passes none. A non-2xx throws with the status and body text —
 * the body is Polar's error for OUR input (product_id / customer_id), never a
 * credential.
 */
export function makePolarClient(opts: {
	token: string;
	apiBase: string;
	fetchImpl?: typeof fetch;
	signal?: AbortSignal;
	userAgent?: string;
}): PolarClient {
	const fetchImpl = opts.fetchImpl ?? fetch;
	async function req(
		method: string,
		path: string,
		body?: unknown,
		bearer: string = opts.token,
	) {
		const res = await fetchImpl(`${opts.apiBase}${path}`, {
			method,
			headers: {
				authorization: `Bearer ${bearer}`,
				"content-type": "application/json",
				"user-agent": opts.userAgent ?? "tracelane-polar-pair/1",
			},
			body: body === undefined ? undefined : JSON.stringify(body),
			...(opts.signal ? { signal: opts.signal } : {}),
		});
		if (!res.ok) {
			// `.claude/rules/billing.md`: a Polar 401/403 body can echo the Bearer
			// token — never carry it into a log line or a stored reason. Every
			// other status's body is Polar's error for OUR input, kept (bounded).
			const text =
				res.status === 401 || res.status === 403
					? "<body withheld: may echo the token>"
					: (await res.text().catch(() => "")).slice(0, 500);
			throw new Error(`Polar ${method} ${path} -> ${res.status}: ${text}`);
		}
		if (res.status === 204) return null;
		return res.json();
	}
	return {
		get: (p) => req("GET", p),
		post: (p, b) => req("POST", p, b),
		patch: (p, b) => req("PATCH", p, b),
		patchAs: (bearer, p, b) => req("PATCH", p, b, bearer),
	};
}

export type PairUsageResult =
	| {
			ok: true;
			applied: true;
			usageSubscriptionId: string;
			/** The card now set as the customer's default — null when there was no
			 *  card, or when setting it failed (then `defaultCardError` says why). */
			defaultPaymentMethodId: string | null;
			defaultCardError?: string;
	  }
	| {
			ok: true;
			applied: false;
			usageSubscriptionId: null;
			defaultPaymentMethodId: string | null;
	  }
	| { ok: false; reason: string; defaultPaymentMethodId?: string | null };

function errorText(err: unknown): string {
	if (err instanceof Error) return err.message;
	return String(err);
}

/**
 * Create the `<plan>_v1_usage_month` subscription on the customer that holds
 * the paid annual base — the calls above, in that order.
 *
 * `apply: false` is the reconciler's `--check`: it reads the payment methods
 * (so the report can name the card) and writes nothing. A missing card does
 * NOT stop the POST — that is the reconciler's behaviour as built and proven
 * in the sandbox; the result names the null default so the caller can log it.
 *
 * Never throws: a Polar refusal, a network fault or an aborted deadline comes
 * back as `{ ok: false, reason }` with Polar's own text.
 */
export async function pairUsageSubscription(args: {
	polar: PolarClient;
	customerId: string;
	usageProductId: string | null;
	apply: boolean;
}): Promise<PairUsageResult> {
	const { polar, customerId, usageProductId, apply } = args;
	let card: { id: string } | null = null;
	try {
		const methods = (await polar.get(
			`/v1/customers/${customerId}/payment-methods`,
		)) as { items?: { id: string; type: string }[] } | null;
		card = (methods?.items ?? []).find((m) => m.type === "card") ?? null;
	} catch (err) {
		return { ok: false, reason: errorText(err) };
	}
	if (!apply) {
		return {
			ok: true,
			applied: false,
			usageSubscriptionId: null,
			defaultPaymentMethodId: card?.id ?? null,
		};
	}
	if (!usageProductId) {
		// Never POST an empty product_id: the plan has no usage product in
		// `plan_entitlements` (polar-sync has not run for this deployment).
		return {
			ok: false,
			reason: "no usage product id configured for this plan",
			defaultPaymentMethodId: card?.id ?? null,
		};
	}
	// Steps 2+3: make the saved card the default THROUGH THE PORTAL API (B-435).
	// A failure here is NOT fatal — the usage subscription still carries the
	// monthly allowances and bills nothing until overage — but it is never
	// silent: the result names it and the caller logs it.
	let defaultSet: string | null = null;
	let defaultCardError: string | undefined;
	if (card) {
		try {
			const session = (await polar.post("/v1/customer-sessions/", {
				customer_id: customerId,
			})) as { token?: unknown } | null;
			const token = typeof session?.token === "string" ? session.token : null;
			if (!token) {
				throw new Error(
					"Polar POST /v1/customer-sessions/ returned no session token",
				);
			}
			await polar.patchAs(token, "/v1/customer-portal/customers/me", {
				default_payment_method_id: card.id,
			});
			defaultSet = card.id;
		} catch (err) {
			defaultCardError = errorText(err);
		}
	}
	try {
		const created = (await polar.post("/v1/subscriptions/", {
			product_id: usageProductId,
			customer_id: customerId,
		})) as { id?: unknown } | null;
		const id = typeof created?.id === "string" ? created.id : null;
		if (!id) {
			return {
				ok: false,
				reason: "Polar POST /v1/subscriptions/ returned no subscription id",
				defaultPaymentMethodId: defaultSet,
			};
		}
		return {
			ok: true,
			applied: true,
			usageSubscriptionId: id,
			defaultPaymentMethodId: defaultSet,
			...(defaultCardError ? { defaultCardError } : {}),
		};
	} catch (err) {
		return {
			ok: false,
			reason: errorText(err),
			defaultPaymentMethodId: defaultSet,
		};
	}
}
