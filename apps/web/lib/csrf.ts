/**
 * Cross-origin mutation refusal for every cookie-authenticated route (2026-10-29 SRE review).
 *
 * The session cookie is SameSite=Lax, so it rides every SAME-SITE request — including a
 * `text/plain` form POST from any `*.tracelane.dev` origin (the marketing site, the docs
 * host). Route handlers parse JSON regardless of Content-Type, so before this only the
 * gateway-control relay (which carried its own copy of this rule) was protected.
 *
 * The rule is the relay's, now in one place: a state-changing request needs POSITIVE proof
 * it came from this app — `Sec-Fetch-Site: same-origin` (browser-set, unforgeable by page
 * script) or an `Origin` exactly equal to the app's own. A request with neither is refused:
 * no browser that matters omits both on a cross-origin POST, and a non-browser client has no
 * session cookie to abuse. Server-to-server callers authenticate by signature instead, so
 * their paths are exempt by exact prefix.
 */

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Exact path prefixes for signed server-to-server callers (HMAC-verified in the handler). */
const EXEMPT_PREFIXES = ["/api/webhooks/"];

export interface MutationRequest {
	method: string;
	url: string;
	headers: Headers;
}

/** True when the request must be refused 403 before any handler runs. */
export function refuseCrossOriginMutation(req: MutationRequest): boolean {
	if (SAFE_METHODS.has(req.method.toUpperCase())) return false;
	const url = new URL(req.url);
	if (EXEMPT_PREFIXES.some((p) => url.pathname.startsWith(p))) return false;
	if (req.headers.get("sec-fetch-site") === "same-origin") return false;
	const origin = req.headers.get("origin");
	return origin === null || origin !== url.origin;
}
