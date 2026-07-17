/**
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

/** Typed gateway error carrying the upstream HTTP status. */
export class GatewayError extends Error {
	constructor(
		readonly status: number,
		message: string,
	) {
		super(message);
		this.name = "GatewayError";
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
	return (await res.json()) as T;
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
