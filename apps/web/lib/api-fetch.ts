/**
 * `apiFetch` — the one client-side fetch for our own `/api/*` routes.
 *
 * WHY THIS EXISTS. Every client island fetched with bare `fetch()` and threw on a
 * non-ok response:
 *
 *     const res = await fetch("/api/settings/team");
 *     if (!res.ok) throw new Error(`HTTP ${res.status}`);
 *     return res.json();
 *
 * That is correct for a 4xx and WRONG for an expired session, because our API routes
 * do not answer 401 — they answer **307 to /sign-in**. `fetch` follows the redirect
 * by default, so the response is the sign-in page: `res.ok` is TRUE, status 200, body
 * HTML. The `throw` never fires; `res.json()` then dies on `<!DOCTYPE`, React Query
 * surfaces it, and the page renders "Something went wrong".
 *
 * MEASURED on prod with a 4-hour-old session: /plans, /prompts and /settings/team all
 * showed the error boundary while the server render itself reported `outcome: "ok"` —
 * the failure was entirely in the browser, which is why the Worker log was clean.
 *
 * "Something went wrong" is the worst possible copy for this: the session simply
 * expired, and the user needs to sign in, not retry.
 *
 * THE FIX IS TO NOTICE THE REDIRECT, and there are two independent tells:
 *   · `res.redirected` is true, or the final URL is the sign-in page;
 *   · the content-type is HTML where JSON was expected.
 * Either one means "you are signed out", so we navigate the whole page to sign-in
 * rather than resolving or throwing. A full navigation (not a router push) is
 * deliberate: the RSC payload is also stale, so re-mounting the client tree against
 * it would fail again.
 */

/** Thrown for a genuine API error, so callers can still branch on status. */
export class ApiError extends Error {
	constructor(
		readonly status: number,
		message?: string,
	) {
		super(message ?? `HTTP ${status}`);
		this.name = "ApiError";
	}
}

function looksSignedOut(res: Response): boolean {
	// Redirected to the auth surface — the 307 our routes actually send.
	if (res.redirected && /\/sign-in|authkit/.test(res.url)) return true;
	if (/\/sign-in|authkit/.test(res.url)) return true;
	// HTML where JSON belongs: the sign-in page arriving with a 200.
	const ct = res.headers.get("content-type") ?? "";
	return res.ok && ct.includes("text/html");
}

/**
 * Fetch one of our own `/api/*` routes and parse JSON.
 *
 * @throws {ApiError} on a real non-ok response (4xx/5xx that is not a sign-out).
 *   A signed-out response never returns and never throws — it navigates.
 */
export async function apiFetch<T>(
	input: string,
	init?: RequestInit,
): Promise<T> {
	const res = await fetch(input, init);

	if (looksSignedOut(res)) {
		// Never resolve and never throw: both would render a broken surface. Hand the
		// browser to sign-in and leave a promise that never settles, so no consumer
		// renders against a signed-out response in the frames before navigation.
		if (typeof window !== "undefined") {
			window.location.href = "/sign-in";
		}
		return new Promise<never>(() => {});
	}

	if (!res.ok) {
		// Preserve the body message when the route sent one — several surfaces render
		// `err.error` as a sentence (seat caps, entitlement copy), and collapsing every
		// failure to "HTTP 4xx" is what made a seat-cap hit unreadable.
		const body = (await res.json().catch(() => null)) as {
			error?: string;
		} | null;
		throw new ApiError(res.status, body?.error);
	}

	return res.json() as Promise<T>;
}
