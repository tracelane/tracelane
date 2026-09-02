/**
 * Server-side gateway proxy (Option 1).
 *
 * The dashboard runs off-node (Vercel) and cannot reach ClickHouse, which is
 * on-node only. ALL trace + SLO reads go through the Rust gateway's authed
 * `/v1/*` endpoints instead of querying ClickHouse directly. This module is the
 * single proxy seam — it mirrors `app/api/settings/provider-keys/*`:
 *
 *   - mints the user's WorkOS access token via `requireGatewayToken()`
 *   - forwards it as `Authorization: Bearer <jwt>`
 *   - the gateway resolves `org_id → internal tenant UUID` (ADR-042) and binds
 *     it into `WHERE tenant_id = ?`. The dashboard NEVER binds a tenant id into
 *     a query — that was the org_id→tenant-UUID seam bug this refactor closes.
 *
 * Fail-loud: in production a missing `NEXT_PUBLIC_GATEWAY_URL` throws rather
 * than silently falling back to localhost (a wrong/absent gateway URL in prod
 * is exactly the "traces never show up" failure we are closing).
 */

import { requireGatewayToken } from "@/lib/auth";

/**
 * Resolve the gateway base URL (no trailing slash). Throws in production when
 * `NEXT_PUBLIC_GATEWAY_URL` is unset; dev falls back to localhost:8080.
 *
 * We forward the user's WorkOS access token as a Bearer to this origin, so the
 * URL is validated (opus-review M1): in production it MUST be `https://`, and
 * it must never carry a query string or fragment (we append a fully-formed path
 * ourselves). A typo'd/compromised env var must fail loud, not ship the token
 * to the wrong host.
 */
export function gatewayBaseUrl(): string {
	const raw = process.env.NEXT_PUBLIC_GATEWAY_URL;
	const isProd = process.env.NODE_ENV === "production";

	if (!raw || raw.length === 0) {
		if (isProd) {
			throw new Error(
				"NEXT_PUBLIC_GATEWAY_URL is required in production — refusing to read traces without a gateway target",
			);
		}
		return "http://localhost:8080";
	}

	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		throw new Error("NEXT_PUBLIC_GATEWAY_URL is not a valid URL");
	}
	if (isProd && url.protocol !== "https:") {
		throw new Error("NEXT_PUBLIC_GATEWAY_URL must use https:// in production");
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") {
		throw new Error("NEXT_PUBLIC_GATEWAY_URL must be an http(s) URL");
	}
	if (url.search !== "" || url.hash !== "") {
		throw new Error(
			"NEXT_PUBLIC_GATEWAY_URL must not include a query string or fragment",
		);
	}
	return raw.replace(/\/$/, "");
}

/**
 * Hard ceiling on a single gateway subrequest. A safety net, not a tuning knob:
 * the gateway answers in ~1ms on-node, so this only ever fires on a genuine
 * stall. See the note at the `signal:` site in `gatewayGet`.
 */
const GATEWAY_TIMEOUT_MS = 10_000;

/**
 * Typed gateway error carrying the upstream HTTP status **and its body**.
 *
 * The gateway's refusals are typed and each one carries the fields a page needs
 * to say something useful — `required_role` on a role 403, `budget_usd` /
 * `spent_usd` / `resets_at` on a budget 402, `items` / `max_items` on a
 * `dataset_too_large` 400. Keeping only the status discarded all of it at the
 * boundary and forced every caller to invent a generic message, which is the
 * "role 403 reads as a generic failure" shape one layer up.
 *
 * `body` is `null` when the upstream sent no body or sent one that is not a JSON
 * object — never `{}`, because "it sent nothing" and "it sent an empty object"
 * are different facts and a caller that reads a field off `{}` would get
 * `undefined` either way with no idea which happened.
 */
export class GatewayError extends Error {
	constructor(
		readonly status: number,
		message: string,
		readonly body: Record<string, unknown> | null = null,
	) {
		super(message);
		this.name = "GatewayError";
	}
}

/**
 * Read an error response's body, best-effort. Runs ONLY on the failure path, so
 * it costs nothing in normal operation.
 *
 * Swallows its own failures deliberately: a body that will not read or will not
 * parse must degrade to `null` and let the STATUS carry the answer, never turn a
 * clean 404 into a thrown exception the caller did not expect.
 */
async function readErrorBody(
	res: Response,
): Promise<Record<string, unknown> | null> {
	try {
		const text = await res.text();
		if (!text) return null;
		const parsed: unknown = JSON.parse(text);
		return parsed !== null &&
			typeof parsed === "object" &&
			!Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

/**
 * GET `path` on the gateway, forwarding the user's Bearer token. Returns the
 * parsed JSON body. Throws `GatewayError` on a non-2xx response (carrying the
 * status) or a transport failure (status 503).
 *
 * `path` must include the leading slash and any query string, e.g.
 * `/v1/traces?limit=50`.
 */
export async function gatewayGet<T>(path: string): Promise<T> {
	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();

	let res: Response;
	try {
		res = await fetch(`${base}${path}`, {
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
			// Bound the tail. There was NO timeout here, so a single stalled
			// subrequest held the whole page open — and /dashboard fans out to
			// eight of these in a Promise.all, so it waits for the slowest one.
			// The gateway answers /health in 0.9ms on-node, so 10s is three orders
			// of magnitude above any legitimate response: it cannot fire in normal
			// operation, it only converts an indefinite hang into a GatewayError
			// that degrades the affected card to its warming state.
			signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
		});
	} catch (err) {
		throw new GatewayError(
			503,
			`gateway unreachable: ${err instanceof Error ? err.message : "fetch failed"}`,
		);
	}

	if (!res.ok) {
		throw new GatewayError(
			res.status,
			`gateway responded ${res.status}`,
			await readErrorBody(res),
		);
	}
	return (await res.json()) as T;
}

/**
 * POST a JSON body to the gateway with the per-user WorkOS JWT as the Bearer,
 * and parse the JSON response. Mirrors {@link gatewayGet}: the gateway resolves
 * the tenant from the token (never the body), so callers pass only the payload.
 * A non-2xx becomes a {@link GatewayError} carrying the status, letting callers
 * map it to their own response.
 */
export async function gatewayPost<T>(path: string, body: unknown): Promise<T> {
	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();

	let res: Response;
	try {
		res = await fetch(`${base}${path}`, {
			method: "POST",
			headers: {
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
			},
			body: JSON.stringify(body),
			cache: "no-store",
			signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
		});
	} catch (err) {
		throw new GatewayError(
			503,
			`gateway unreachable: ${err instanceof Error ? err.message : "fetch failed"}`,
		);
	}

	if (!res.ok) {
		throw new GatewayError(
			res.status,
			`gateway responded ${res.status}`,
			await readErrorBody(res),
		);
	}
	return (await res.json()) as T;
}

/**
 * PATCH a gateway resource with the per-user WorkOS JWT as the Bearer.
 *
 * Identical to {@link gatewayPost} but for a partial update. It exists rather
 * than folding an update into POST because the gateway route IS a PATCH: a
 * proxy that changes the verb makes the two sides disagree about what a partial
 * update means, and the first casualty is the "unset this field" case.
 */
export async function gatewayPatch<T>(path: string, body: unknown): Promise<T> {
	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();

	let res: Response;
	try {
		res = await fetch(`${base}${path}`, {
			method: "PATCH",
			headers: {
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
			},
			body: JSON.stringify(body),
			cache: "no-store",
			signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
		});
	} catch (err) {
		throw new GatewayError(
			503,
			`gateway unreachable: ${err instanceof Error ? err.message : "fetch failed"}`,
		);
	}

	if (!res.ok) {
		throw new GatewayError(
			res.status,
			`gateway responded ${res.status}`,
			await readErrorBody(res),
		);
	}
	return (await res.json()) as T;
}

/**
 * DELETE a gateway resource with the per-user WorkOS JWT as the Bearer.
 *
 * Returns nothing: the gateway answers a successful delete with **204 No
 * Content**, so there is no body to parse and this deliberately does not try —
 * `gatewayPost`'s `res.json()` would throw on an empty body and turn a
 * successful revoke into a 500 the user reads as "it failed" while the row is
 * already gone.
 *
 * A non-2xx becomes a {@link GatewayError} carrying the status, so callers can
 * distinguish 403 (not an owner) from 404 (no such pin) rather than collapsing
 * both into one message — the failure mode recorded for the role-403 path.
 */
export async function gatewayDelete(path: string): Promise<void> {
	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();

	let res: Response;
	try {
		res = await fetch(`${base}${path}`, {
			method: "DELETE",
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
			signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
		});
	} catch (err) {
		throw new GatewayError(
			503,
			`gateway unreachable: ${err instanceof Error ? err.message : "fetch failed"}`,
		);
	}

	if (!res.ok) {
		throw new GatewayError(res.status, `gateway responded ${res.status}`);
	}
}

/**
 * Like {@link gatewayGet} but returns `null` on a 404 instead of throwing.
 * Used for the trace-detail view: the gateway returns the SAME 404 for "trace
 * does not exist" and "trace belongs to another tenant", so a null result
 * never reveals cross-tenant existence.
 */
export async function gatewayGetOrNull<T>(path: string): Promise<T | null> {
	try {
		return await gatewayGet<T>(path);
	} catch (err) {
		if (err instanceof GatewayError && err.status === 404) return null;
		throw err;
	}
}

/**
 * Like {@link gatewayGet} but returns the raw response BODY as text. Used for
 * the NDJSON audit-ledger export, which the dashboard hands to the client-side
 * verifier rather than parsing as JSON.
 */
export async function gatewayGetText(path: string): Promise<string> {
	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();
	let res: Response;
	try {
		res = await fetch(`${base}${path}`, {
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
			signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
		});
	} catch (err) {
		throw new GatewayError(
			503,
			`gateway unreachable: ${err instanceof Error ? err.message : "fetch failed"}`,
		);
	}
	if (!res.ok) {
		throw new GatewayError(res.status, `gateway responded ${res.status}`);
	}
	return await res.text();
}

/**
 * Copy a whitelist of query params from an incoming request into a new
 * `URLSearchParams`, dropping empty values. Keeps the dashboard API routes
 * thin pass-throughs to the gateway.
 */
export function forwardParams(
	src: URLSearchParams,
	keys: readonly string[],
): URLSearchParams {
	const out = new URLSearchParams();
	for (const k of keys) {
		const v = src.get(k);
		if (v !== null && v !== "") out.set(k, v);
	}
	return out;
}
