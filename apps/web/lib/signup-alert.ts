/**
 * signup-alert.ts — PLT-53: tell the operator when a new workspace signs up.
 *
 * Fail-OPEN (CLAUDE.md §10): a notification, never a control. Nothing here throws,
 * and the caller schedules it after the response (`after()`), so sign-up succeeds
 * whether Resend answers, errors, hangs or is not configured.
 *
 * ONCE per workspace, by the same three layers as the welcome email (PLT-52):
 *   1. structural: the only caller is the fresh-provisioning branch of
 *      `POST /api/onboarding/organization`;
 *   2. per isolate: `handled` remembers org ids already attempted;
 *   3. provider: `Idempotency-Key: signup-alert-<org id>` (Resend drops a repeat for 24 h).
 *
 * The notice goes to the OPERATOR (`SIGNUP_ALERT_TO`, default the founder address the
 * welcome email already replies to), never to the person who signed up. So it is sent
 * for unverified addresses too, and says which. The subject carries no user text; the
 * HTML part escapes every user field.
 */

import { sendEmail } from "@/lib/email";
import { formatDateTimeUtc } from "@/lib/format-date";
import {
	OPERATOR_INBOX,
	plainAddress,
	sanitizeUserText as sanitizeText,
} from "@/lib/operator-notice";
import { rateLimit } from "@/lib/rate-limit";
import { escapeHtml } from "@/lib/welcome-email";
import { after } from "next/server";

const DEFAULT_TO = OPERATOR_INBOX;
const SUBJECT = "New Tracelane signup";
// The workspace name is user-supplied and rides in mail from our own domain. Strip control,
// format (bidi overrides, zero-width) and line/paragraph separators, collapse whitespace and
// cap the length, so it cannot forge extra rows, reorder text or bury the real fields.
const NAME_MAX = 100;
// Global ceiling on alerts per hour across every account: a scripted sign-up flood must
// not turn the operator inbox (and our sending reputation) into its target. Measured
// baseline: prod signups are single digits per week (2026-11-14), so 50/h is ~100x headroom.
const GLOBAL_CAP_PER_HOUR = 50;
const HOUR_MS = 60 * 60_000;

/** Neutralise a user-supplied display string for an operator notice. */
export function sanitizeUserText(s: string, max = NAME_MAX): string {
	return sanitizeText(s, max);
}

export interface SignupAlertInput {
	/** WorkOS organization id of the workspace just created. Keys the dedupe. */
	workspaceId: string;
	/** Workspace display name, or null. User-supplied. */
	workspaceName: string | null;
	/** Internal tenant UUID. */
	tenantId: string;
	/** The WorkOS session user's email. */
	email: string;
	emailVerified: boolean;
	at: Date;
}

export type SignupAlertResult = "sent" | "skipped" | "duplicate" | "failed";

/** Plain notice. Text is not escaped (plain text); HTML escapes every user field. */
export function buildSignupAlert(input: SignupAlertInput): {
	subject: string;
	text: string;
	html: string;
} {
	const iso = input.at.toISOString();
	const rows: [string, string][] = [
		["email", sanitizeUserText(input.email, 320)],
		["email verified", input.emailVerified ? "yes" : "no"],
		["workspace id", input.workspaceId],
		["tenant id", input.tenantId],
		["signed up", `${formatDateTimeUtc(iso)} (${iso})`],
		// Last, and labelled: the only free-text field, typed by the person signing up.
		[
			"workspace name (user-supplied)",
			input.workspaceName ? sanitizeUserText(input.workspaceName) : "(unnamed)",
		],
	];
	const text = [
		"A new workspace was created on Tracelane.",
		"",
		...rows.map(([k, v]) => `${k}: ${v}`),
		"",
	].join("\n");
	const html = [
		"<p>A new workspace was created on Tracelane.</p>",
		"<table>",
		...rows.map(
			([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`,
		),
		"</table>",
	].join("\n");
	return { subject: SUBJECT, text, html };
}

// Per-isolate state. Sign-ups are rare; the cap only guards a long-lived isolate.
const handled = new Set<string>();
const HANDLED_CAP = 1000;
let warnedUnconfigured = false;
let warnedCapped = false;

/** Test seam: reset the per-isolate state. Not used by production code. */
export function resetSignupAlertStateForTests(): void {
	handled.clear();
	warnedUnconfigured = false;
	warnedCapped = false;
}

/** Send the notice. Resolves, never rejects. Logs carry the org id, never an address. */
export async function sendSignupAlert(
	input: SignupAlertInput,
): Promise<SignupAlertResult> {
	try {
		const key = process.env.RESEND_API_KEY;
		const from = process.env.RESEND_FROM;
		const to = process.env.SIGNUP_ALERT_TO || DEFAULT_TO;
		if (!key || !from || !plainAddress(to)) {
			// Degraded state entered: one line per isolate, not per sign-up (logging.md).
			if (!warnedUnconfigured) {
				warnedUnconfigured = true;
				console.warn(
					JSON.stringify({
						event: "signup_alert_skipped",
						marker: "TRACELANE_DEGRADED email_unconfigured",
						reason: !key
							? "RESEND_API_KEY unset"
							: !from
								? "RESEND_FROM unset"
								: "SIGNUP_ALERT_TO not a plain address",
					}),
				);
			}
			return "skipped";
		}
		if (handled.has(input.workspaceId)) return "duplicate";
		if (handled.size >= HANDLED_CAP) handled.clear();
		handled.add(input.workspaceId);

		// # Errors: counter unavailable -> skip the send (fail-CLOSED on the notice, so a
		// broken counter can never mean an unbounded send); sign-up is unaffected (fail-OPEN).
		let underCap = false;
		try {
			underCap = await rateLimit(
				"signup-alert:global",
				GLOBAL_CAP_PER_HOUR,
				HOUR_MS,
			);
		} catch {
			underCap = false;
		}
		if (!underCap) {
			// First cap hit per isolate carries the degraded marker so a flood is visible;
			// later hits are plain lines (logging.md: enter the state loudly, then count).
			console.warn(
				JSON.stringify({
					event: "signup_alert_capped",
					workspace: input.workspaceId,
					...(warnedCapped
						? {}
						: { marker: "TRACELANE_DEGRADED signup_alert_capped" }),
				}),
			);
			warnedCapped = true;
			return "skipped";
		}

		const { subject, text, html } = buildSignupAlert(input);
		const ok = await sendEmail({
			to,
			from,
			subject,
			text,
			html,
			idempotencyKey: `signup-alert-${input.workspaceId}`,
		});
		if (!ok) {
			console.error(
				JSON.stringify({
					event: "signup_alert_failed",
					workspace: input.workspaceId,
				}),
			);
			return "failed";
		}
		return "sent";
	} catch (err) {
		console.error(
			JSON.stringify({
				event: "signup_alert_failed",
				workspace: input.workspaceId,
				error: err instanceof Error ? err.name : "unknown",
			}),
		);
		return "failed";
	}
}

/** Schedule the send after the response (see `scheduleWelcomeEmail`). Never throws. */
export function scheduleSignupAlert(input: SignupAlertInput): void {
	try {
		after(() => sendSignupAlert(input));
	} catch {
		void sendSignupAlert(input);
	}
}
