/**
 * Pure validation for the self-serve email change (SET-26).
 *
 * Separate from `route.ts` because a Next.js Route Handler module may only
 * export HTTP verbs and route config — a helper exported beside `POST` fails
 * the framework's route type check. It is also the half worth testing directly:
 * the whole security posture of an email change is in what it REFUSES.
 *
 * ## Threat model this encodes
 *
 * Changing the address on an account is an account-takeover primitive: whoever
 * owns the address owns the password-reset path. There is no re-auth prompt at
 * launch (IDENTITY_TEAM_SPEC §6 accepts type-to-confirm as the compensating
 * control), so the confirmations below ARE the control:
 *
 *   1. the caller must retype their CURRENT address — proves they know whose
 *      account the live session belongs to, not just that they hold a cookie;
 *   2. the caller must type the NEW address twice — a typo'd address is an
 *      irreversible lockout, so a single field is not enough;
 *   3. the new address must actually differ, so a no-op cannot silently reset
 *      `email_verified` and force a re-verification the user did not ask for.
 *
 * Every check FAILS CLOSED: anything not positively validated is rejected.
 */

/**
 * The URL the browser posts an email change to. It is the path of the route
 * handler sitting beside this file, named once so the client cannot drift off
 * the endpoint into a silent 404 when the route moves.
 */
export const EMAIL_CHANGE_ENDPOINT = "/settings/account/email";

/** Maximum accepted address length. Matches the 255-char `name` bound the
 * sibling profile handler uses, and is comfortably above RFC 5321's 254. */
const MAX_EMAIL_LEN = 254;

/**
 * Deliberately strict, deliberately not RFC 5322. A permissive regex is the
 * wrong trade here: the cost of rejecting an exotic-but-legal address is a
 * support ticket, while the cost of accepting a malformed one is an account
 * whose recovery address does not resolve. Requires exactly one `@`, a
 * non-empty local part, a dotted domain, no whitespace, no angle brackets.
 */
const EMAIL_RE = /^[^\s@<>",;:\\]+@[^\s@<>",;:\\.]+(\.[^\s@<>",;:\\.]+)+$/;

export type EmailChangeError =
	| "invalid_json"
	| "email_required"
	| "email_invalid"
	| "email_too_long"
	| "confirmation_mismatch"
	| "current_email_mismatch"
	| "email_unchanged";

export interface EmailChangeRequest {
	/** The address the caller wants to move to, normalised to lower case. */
	newEmail: string;
}

export type EmailChangeValidation =
	| { ok: true; value: EmailChangeRequest }
	| { ok: false; error: EmailChangeError; detail: string };

/** Case-insensitive address comparison. Addresses are compared, never secrets,
 * so a plain compare is correct — there is nothing here to time-attack. */
function sameAddress(a: string, b: string): boolean {
	return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Validate an email-change request against the session's current address.
 *
 * `currentEmail` MUST come from the validated session, never from the request
 * body — otherwise the "retype your current address" control is one the attacker
 * fills in themselves.
 *
 * # Errors
 *
 * Fails CLOSED. Every branch that is not a positively-validated change returns
 * `ok: false`; there is no permissive fallthrough.
 */
export function validateEmailChange(
	body: unknown,
	currentEmail: string,
): EmailChangeValidation {
	if (typeof body !== "object" || body === null) {
		return {
			ok: false,
			error: "invalid_json",
			detail: "request body must be a JSON object",
		};
	}
	const b = body as Record<string, unknown>;
	const newEmail = typeof b.newEmail === "string" ? b.newEmail.trim() : "";
	const confirmEmail =
		typeof b.confirmEmail === "string" ? b.confirmEmail.trim() : "";
	const confirmCurrentEmail =
		typeof b.confirmCurrentEmail === "string"
			? b.confirmCurrentEmail.trim()
			: "";

	if (!newEmail) {
		return {
			ok: false,
			error: "email_required",
			detail: "a new email address is required",
		};
	}
	if (newEmail.length > MAX_EMAIL_LEN) {
		return {
			ok: false,
			error: "email_too_long",
			detail: `email must be ${MAX_EMAIL_LEN} characters or fewer`,
		};
	}
	if (!EMAIL_RE.test(newEmail)) {
		return {
			ok: false,
			error: "email_invalid",
			detail: "that does not look like an email address",
		};
	}
	// Control 2 — typed twice. Checked BEFORE the current-address control so a
	// typo is reported as a typo rather than as a failed confirmation.
	if (!sameAddress(newEmail, confirmEmail)) {
		return {
			ok: false,
			error: "confirmation_mismatch",
			detail: "the two new-address fields do not match",
		};
	}
	// Control 1 — prove whose account this session is.
	if (!sameAddress(confirmCurrentEmail, currentEmail)) {
		return {
			ok: false,
			error: "current_email_mismatch",
			detail: "type your current email address exactly to confirm",
		};
	}
	// Control 3 — a no-op must not reset email_verified.
	if (sameAddress(newEmail, currentEmail)) {
		return {
			ok: false,
			error: "email_unchanged",
			detail: "that is already your email address",
		};
	}

	return { ok: true, value: { newEmail: newEmail.toLowerCase() } };
}

/**
 * Client-side mirror of the submit gate: may the "Change email" button be
 * pressed at all? Shares no code path with server enforcement on purpose — this
 * is UX, the server is the control — but shares the same rules so the button is
 * never enabled on a request the server would refuse.
 */
export function canSubmitEmailChange(input: {
	currentEmail: string;
	newEmail: string;
	confirmEmail: string;
	confirmCurrentEmail: string;
}): boolean {
	const v = validateEmailChange(
		{
			newEmail: input.newEmail,
			confirmEmail: input.confirmEmail,
			confirmCurrentEmail: input.confirmCurrentEmail,
		},
		input.currentEmail,
	);
	return v.ok;
}
