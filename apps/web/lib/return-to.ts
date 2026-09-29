/**
 * The path to resume after signing in again — or `undefined` when the value is not a
 * safe SAME-ORIGIN app path. Refused: anything not starting with a single "/", a
 * protocol-relative "//host", a backslash (browsers normalise "/\\host" to "//host"),
 * the auth routes themselves (a return to /sign-in would loop), and `/api/` (resuming a
 * JSON endpoint after sign-in would show raw JSON; the client passes its PAGE instead).
 */
export function safeReturnTo(
	raw: string | null | undefined,
): string | undefined {
	if (!raw || raw.length > 2048) return undefined;
	if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\"))
		return undefined;
	if (/^\/(sign-in|sign-out|auth|api)(\/|\?|$)/.test(raw)) return undefined;
	return raw;
}

/**
 * `/sign-in`, carrying the page the request was for — read from AuthKit's `x-url`
 * request header (its middleware stores the full request URL there). Server-side only.
 * Falls back to plain `/sign-in` when the header is absent or unsafe.
 */
export async function signInPath(): Promise<string> {
	try {
		const { headers } = await import("next/headers");
		const raw = (await headers()).get("x-url");
		if (!raw) return "/sign-in";
		const u = new URL(raw);
		const back = safeReturnTo(`${u.pathname}${u.search}`);
		return back ? `/sign-in?returnTo=${encodeURIComponent(back)}` : "/sign-in";
	} catch {
		return "/sign-in";
	}
}
