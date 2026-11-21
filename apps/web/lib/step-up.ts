/**
 * ACT-41 — approving a held call needs a recent sign-in (`specs/ACT-41-approver-step-up.md`).
 * The gateway decides (it checks the signed `auth_time` of the access token); this file only
 * builds the way back: a link to `/sign-in?reauth=1`, and the forced AuthKit URL.
 */
import { safeReturnTo } from "./return-to";

/**
 * Force a fresh sign-in on an AuthKit authorize URL. `max_age=0` is the WorkOS wire
 * parameter ("0 forces re-authentication"); `@workos-inc/authkit-nextjs` 4.0.1 and
 * `@workos-inc/node` 9.2.0 expose no option for it, so it is set on the URL they return.
 * Throws on a value that is not a URL: a sign-in that silently did not force is worse.
 */
export function forceReauth(authorizeUrl: string): string {
	const u = new URL(authorizeUrl);
	u.searchParams.set("max_age", "0");
	return u.toString();
}

/** `/sign-in?reauth=1`, returning to `path` when it is a safe same-origin app page. */
export function reauthHref(path: string): string {
	const back = safeReturnTo(path);
	return back
		? `/sign-in?reauth=1&returnTo=${encodeURIComponent(back)}`
		: "/sign-in?reauth=1";
}
