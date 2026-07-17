/**
 * Tenant-ID resolution for the MCP server.
 *
 * A2: replaces the V1 process-env stub with two real resolvers:
 *
 *   - **Stdio mode** (Claude Desktop / Cursor subprocess):
 *     `TRACELANE_TENANT_ID` env is still permitted because the MCP
 *     server runs as a trusted subprocess; the Desktop client controls
 *     the env block.
 *
 *   - **HTTP mode** (Streamable HTTP transport for remote callers):
 *     the bearer token from `Authorization: Bearer <token>` is
 *     validated against the gateway's `/v1/auth/whoami` endpoint. The
 *     gateway holds the JWKS, JWT alg allowlist, audience check, and
 *     peppered HMAC API-key lookup — we never duplicate that surface
 *     in Node. Tenant ID returned by the gateway is cached in-process
 *     for 60s (keyed by the bearer string) so hot-path latency stays
 *     low without weakening revocation semantics.
 *
 * Tool handlers no longer call `getTenantId()` from module scope — the
 * HTTP middleware sets a per-request `currentTenantId` via
 * `runWithTenant(tenant, fn)` and tools read it via `getTenantId()`.
 */

import { AsyncLocalStorage } from "node:async_hooks";

interface AuthContext {
	tenantId: string;
}

const als = new AsyncLocalStorage<AuthContext>();

/**
 * Bind a tenant to the current async chain for the duration of `fn`.
 * Used by the HTTP transport's middleware to give each request its own
 * tenant context.
 */
export async function runWithTenant<T>(
	tenantId: string,
	fn: () => Promise<T>,
): Promise<T> {
	return als.run({ tenantId }, fn);
}

/**
 * Resolve the active tenant ID. Looks at the AsyncLocalStorage context
 * first (HTTP mode), falls back to `TRACELANE_TENANT_ID` env (Stdio
 * mode). Throws if neither is set.
 */
export function getTenantId(): string {
	const ctx = als.getStore();
	if (ctx?.tenantId) return ctx.tenantId;

	// Stdio: the gateway-VALIDATED tenant (from TRACELANE_API_KEY, resolved
	// once at startup by bootstrapStdioTenant) beats the raw env id.
	if (stdioTenantId) return stdioTenantId;

	const id = process.env.TRACELANE_TENANT_ID;
	if (!id) {
		throw new Error(
			"No tenant context available. " +
				"For Stdio: set TRACELANE_API_KEY (validated via the gateway) " +
				"or TRACELANE_TENANT_ID. " +
				"For HTTP: ensure the request carried an Authorization: Bearer header.",
		);
	}
	return id;
}

// ---------------------------------------------------------------------
// Stdio API-key tenant bootstrap (L3 sweep, 2026-07-03)
//
// Every published stdio quick-start sets TRACELANE_API_KEY, but the stdio
// path historically read only TRACELANE_TENANT_ID — the documented auth
// flow never executed (the tested resolveBearerViaGateway was reachable
// only from the HTTP transport). This wires the documented path: resolve
// the key ONCE at startup via the gateway whoami and pin the validated
// tenant for the process.
// ---------------------------------------------------------------------

let stdioTenantId: string | null = null;

/** Test hook + bootstrap setter for the process-wide stdio tenant. */
export function setStdioTenantId(id: string | null): void {
	stdioTenantId = id;
}

/**
 * Resolve the stdio tenant from `TRACELANE_API_KEY` via the gateway
 * (`/v1/auth/whoami`) — the documented quick-start path.
 *
 * Fail-closed: a key that is SET but rejected/unreachable throws (the
 * server refuses to start) rather than silently falling back to the
 * unvalidated `TRACELANE_TENANT_ID`. Returns `null` when no key is set
 * (callers fall back to the env id, the pre-existing dev path).
 */
export async function bootstrapStdioTenant(): Promise<string | null> {
	const apiKey = process.env.TRACELANE_API_KEY;
	if (!apiKey) return null;
	const tenantId = await resolveBearerViaGateway(apiKey);
	if (!tenantId) {
		throw new Error(
			"TRACELANE_API_KEY is set but could not be validated against the " +
				"gateway (check the key and TRACELANE_GATEWAY_URL) — refusing " +
				"to start with an unauthenticated tenant context.",
		);
	}
	setStdioTenantId(tenantId);
	return tenantId;
}

// ---------------------------------------------------------------------
// Gateway /v1/auth/whoami proxy + 60s LRU
// ---------------------------------------------------------------------

interface CachedAuth {
	/** `null` = negative cache (auth failed) so an attacker can't
	 * turn the MCP into a credential-stuffing amplifier (C-6). */
	tenantId: string | null;
	expiresAt: number;
}

const cache = new Map<string, CachedAuth>();
const CACHE_TTL_MS = 60_000;
const NEG_CACHE_TTL_MS = 5_000;
const CACHE_MAX_ENTRIES = 4_096;

/**
 * any bearer over the wire. The Node-side MCP would otherwise dispatch
 * customer bearers to whatever the env var resolves to — a misconfigured
 * (or attacker-controlled in a multi-tenant Kubernetes namespace) value
 * could exfiltrate every credential the MCP sees.
 *
 * Validation runs once per `resolveBearerViaGateway` call (cheap URL
 * parse) so a runtime env rotation to a hostile value is caught.
 * Release-mode rejects: http://, private IPv4 literals, RFC1918, CGNAT,
 * loopback, IMDS, and a non-tracelane host.
 *
 * Debug builds (NODE_ENV !== "production") accept loopback so the
 * local dev loop works.
 */
function validateGatewayUrl(
	raw: string,
): { ok: true; url: string } | { ok: false; reason: string } {
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		return { ok: false, reason: "TRACELANE_GATEWAY_URL is not a valid URL" };
	}
	const debugMode = process.env.NODE_ENV !== "production";

	if (parsed.protocol === "http:" && !debugMode) {
		return {
			ok: false,
			reason: "TRACELANE_GATEWAY_URL must be https:// in production",
		};
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		return { ok: false, reason: `unsupported scheme: ${parsed.protocol}` };
	}

	const host = parsed.hostname.toLowerCase();

	// Debug bypass for the local-dev loop.
	if (
		debugMode &&
		(host === "localhost" || host === "127.0.0.1" || host === "::1")
	) {
		return { ok: true, url: raw };
	}

	const blockedLiterals = new Set([
		"169.254.169.254", // AWS / GCP IMDS
		"100.100.100.200", // Alibaba IMDS
		"168.63.129.16", // Azure IMDS
		"metadata.google.internal",
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"::1",
		"::",
	]);
	if (blockedLiterals.has(host)) {
		return { ok: false, reason: `host ${host} is in the SSRF blocklist` };
	}

	const blockedPrefixes = [
		"10.",
		"192.168.",
		"169.254.",
		"172.16.",
		"172.17.",
		"172.18.",
		"172.19.",
		"172.20.",
		"172.21.",
		"172.22.",
		"172.23.",
		"172.24.",
		"172.25.",
		"172.26.",
		"172.27.",
		"172.28.",
		"172.29.",
		"172.30.",
		"172.31.",
		"100.64.",
		"100.65.",
		"100.66.",
		"100.67.",
	];
	if (blockedPrefixes.some((p) => host.startsWith(p))) {
		return { ok: false, reason: `host ${host} is in a private / CGNAT range` };
	}

	// In production, require *.tracelane.dev (or a tracelane.dev apex).
	if (
		!debugMode &&
		host !== "tracelane.dev" &&
		!host.endsWith(".tracelane.dev")
	) {
		return { ok: false, reason: `host ${host} not on tracelane.dev allowlist` };
	}
	return { ok: true, url: raw };
}

/**
 * Resolve the tenant for a bearer string by calling the gateway's
 * `/v1/auth/whoami`. Cached for 60 seconds keyed on the bearer's
 * SHA-256 (we never hold the plaintext token in the cache map's keys).
 *
 * Returns `null` on any auth failure — the HTTP transport handler is
 * expected to surface a 401. Failures are also cached for 5 seconds
 * (mythos round-3 C-6) so a credential-stuffing attacker can't turn
 * the MCP into a `/v1/auth/whoami` amplifier.
 */
export async function resolveBearerViaGateway(
	bearer: string,
): Promise<string | null> {
	if (!bearer) return null;

	const cacheKey = await sha256Hex(bearer);
	const cached = cache.get(cacheKey);
	if (cached && cached.expiresAt > Date.now()) {
		return cached.tenantId;
	}

	const base = process.env.TRACELANE_GATEWAY_URL ?? "http://localhost:8080";
	const validation = validateGatewayUrl(base);
	if (!validation.ok) {
		process.stderr.write(
			`${JSON.stringify({
				level: "error",
				component: "mcp",
				msg: "rejecting TRACELANE_GATEWAY_URL",
				reason: validation.reason,
				ts: new Date().toISOString(),
			})}\n`,
		);
		return null;
	}
	const url = `${validation.url.replace(/\/+$/, "")}/v1/auth/whoami`;
	let resp: Response;
	try {
		resp = await fetch(url, {
			method: "GET",
			headers: { authorization: `Bearer ${bearer}` },
			signal: AbortSignal.timeout(5_000),
		});
	} catch (err) {
		process.stderr.write(
			`${JSON.stringify({
				level: "warn",
				component: "mcp",
				msg: "whoami fetch failed",
				error: err instanceof Error ? err.message : String(err),
			})}\n`,
		);
		return null;
	}
	if (!resp.ok) {
		// Negative cache (C-6) — block credential-stuffing amplification.
		setCached(cacheKey, null, NEG_CACHE_TTL_MS);
		return null;
	}

	// trusted-gateway hop should never return more than a few hundred
	// bytes; cap at 64 KiB so a misbehaving gateway can't OOM the MCP.
	const ct = resp.headers.get("content-length");
	if (ct !== null && Number.parseInt(ct, 10) > 64_000) {
		process.stderr.write(
			`${JSON.stringify({
				level: "warn",
				component: "mcp",
				msg: "gateway whoami response too large",
				content_length: ct,
			})}\n`,
		);
		setCached(cacheKey, null, NEG_CACHE_TTL_MS);
		return null;
	}
	let body: { tenant_id?: string };
	try {
		body = (await resp.json()) as { tenant_id?: string };
	} catch {
		setCached(cacheKey, null, NEG_CACHE_TTL_MS);
		return null;
	}
	if (!body.tenant_id) {
		setCached(cacheKey, null, NEG_CACHE_TTL_MS);
		return null;
	}

	setCached(cacheKey, body.tenant_id, CACHE_TTL_MS);
	return body.tenant_id;
}

function setCached(key: string, tenantId: string | null, ttlMs: number): void {
	// Prune cache if it grew unbounded (rare; just bound memory).
	if (cache.size >= CACHE_MAX_ENTRIES) {
		const firstKey = cache.keys().next().value;
		if (firstKey) cache.delete(firstKey);
	}
	cache.set(key, { tenantId, expiresAt: Date.now() + ttlMs });
}

async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest("SHA-256", data);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}
