/**
 * Build the ONE log line that carries a health-probe's real failure cause,
 * with the credential removed.
 *
 * ## Why this exists
 *
 * `/api/health/deep` deliberately coarsens its RESPONSE to a failure class
 * (`dns` | `conn` | `timeout` | `auth` | `error`) because it is a probe surface
 * and must not name dependency hostnames to an unauthenticated caller. Until
 * 2026-08-24 it also **discarded** the real message, so the class was all anyone
 * ever saw — and `error` is the *fallthrough*, meaning only "none of the other
 * four". Prod sat on `neon: "fail: error"` for ~9 hours while `wrangler tail`
 * showed `exceptions: []`, and the cause had to be inferred by running the driver
 * against eight synthetic failure shapes offline.
 *
 * **The rule: coarsen the RESPONSE, log the CAUSE.** A probe surface that must not
 * leak detail still has somewhere to put it.
 *
 * ## Why redaction is two layers and not one
 *
 * `@neondatabase/serverless` echoes the ENTIRE connection string in its
 * invalid-URL error, so the naive version of this leaks `DATABASE_URL` —
 * password included — into the Worker log. That is B-276's class.
 *
 * B-276's actual lesson is sharper than "redact": its redactor matched only `://`
 * while the failing path had reformatted the scheme to `postgresql:/`, so the
 * pattern walked straight past the credential it existed to catch. **Pattern
 * redaction is not a control on its own.** So:
 *
 *   1. the pattern tolerates one OR two slashes (`:\/{1,2}`), and
 *   2. an EXACT-VALUE check re-reads the result and withholds the whole message
 *      if the credential survived. An exact comparison cannot be walked past by a
 *      reformatted scheme the way a regex can.
 */

/** Strip `scheme://user:pass@` userinfo. One or two slashes — see B-276 above. */
export function redactUserinfo(msg: string): string {
	return msg.replace(/([a-zA-Z][\w+.-]*:\/{1,2})[^/\s@]*@/g, "$1<redacted>@");
}

/** Pull the password out of a connection string, for the exact-value check. */
export function passwordOf(url: string | undefined): string | undefined {
	if (!url) return undefined;
	return (
		url.match(/^[a-zA-Z][\w+.-]*:\/{1,2}[^/\s:@]*:([^@]+)@/)?.[1] || undefined
	);
}

/**
 * The log line. Pure — takes the connection string rather than reading the
 * environment, so a test can drive it with a known credential and assert the
 * credential does not survive.
 */
export function causeLine(dep: string, err: unknown, url?: string): string {
	const name = err instanceof Error ? err.name : typeof err;
	const raw = err instanceof Error ? err.message : String(err);
	const redacted = redactUserinfo(raw).slice(0, 400);
	const pw = passwordOf(url);
	const leaked =
		(!!url && redacted.includes(url)) || (!!pw && redacted.includes(pw));
	return `health/deep ${dep} FAILED: ${name}: ${
		leaked ? "<message withheld — the credential survived redaction>" : redacted
	}`;
}
