/**
 * welcome-email.ts — PLT-52: one welcome email per NEW workspace.
 *
 * Fail-OPEN (CLAUDE.md §10): a notification path, never a control. Nothing in
 * here throws, and the caller schedules it after the response (`after()`), so
 * sign-up succeeds whether Resend answers, errors, hangs or is not configured.
 *
 * Transport is `sendEmail` in `lib/email.ts` (raw `fetch` to Resend, no
 * dependency); this file owns only the copy, the config gate and the dedupe.
 *
 * ONCE per workspace — three layers, none needing a migration (spec PLT-52 §2):
 *   1. structural: the only caller is the fresh-provisioning branch of
 *      `POST /api/onboarding/organization`, which runs only when the user has no
 *      membership yet;
 *   2. per isolate: `handled` remembers org ids already attempted;
 *   3. provider: `Idempotency-Key: welcome-<org id>` (Resend drops a repeat for 24 h).
 *
 * The recipient is the WorkOS session user's email, passed in by the route from
 * `withAuth()` — never from a request body.
 */

import { sendEmail } from "@/lib/email";
import { after } from "next/server";

const SUPPORT = "founder@tracelane.dev"; // founder, 2026-09-30: replies go to the founder directly
const APP = "https://app.tracelane.dev";
// Fixed, not NEXT_PUBLIC_GATEWAY_URL: the email names the hosted gateway, and
// a dev/self-host build must not put localhost into a customer's inbox.
const GATEWAY = "https://gateway.tracelane.dev";
const QUICKSTART = "https://docs.tracelane.dev/quickstart";

export interface WelcomeEmailInput {
	/** WorkOS organization id of the workspace just created. Keys the dedupe. */
	workspaceId: string;
	/** Workspace display name, or null. User-supplied: escaped in the HTML part. */
	workspaceName: string | null;
	/** Recipient — the signed-in user's email from the WorkOS session. */
	to: string;
}

export type WelcomeResult = "sent" | "skipped" | "duplicate" | "failed";

const SUBJECT = "Your Tracelane workspace is ready";

function escapeHtml(s: string): string {
	return s
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

/** Plain-text + minimal HTML. Every URL and step is the one the onboarding
 *  wizard and `apps/docs/quickstart.mdx` already show (spec PLT-52 §8). */
export function buildWelcomeEmail(workspaceName: string | null): {
	subject: string;
	text: string;
	html: string;
} {
	// Security review 2026-09-30 (M1): the workspace name is user text; it never goes into
	// mail sent from founder@tracelane.dev (a link or paragraph in it would read as ours).
	void workspaceName;
	const lead = "Your workspace is ready.";
	const what =
		"Tracelane is the flight recorder for AI agents: point an OpenAI-compatible client at our gateway and each call is recorded as a trace.";
	const s1 = `Create an API key: Settings -> API Keys (${APP}/settings/api-keys). A key is shown once, at creation.`;
	const s2 = `Point your client at ${GATEWAY}/v1 and use the key as its API key.`;
	const s3 = `Open ${APP}/traces and find the call you just made.`;
	const help = `Questions? Reply to this email or write to ${SUPPORT}.`;

	const text = [
		lead,
		what,
		"",
		`1. ${s1}`,
		`2. ${s2}`,
		`3. ${s3}`,
		"",
		`Quickstart: ${QUICKSTART}`,
		help,
		"",
	].join("\n");

	const a = (href: string) => `<a href="${href}">${href}</a>`;
	const html = [
		`<p>${escapeHtml(lead)}</p>`,
		`<p>${escapeHtml(what)}</p>`,
		"<ol>",
		`<li>Create an API key: Settings &rarr; API Keys (${a(`${APP}/settings/api-keys`)}). A key is shown once, at creation.</li>`,
		`<li>Point your client at ${a(`${GATEWAY}/v1`)} and use the key as its API key.</li>`,
		`<li>Open ${a(`${APP}/traces`)} and find the call you just made.</li>`,
		"</ol>",
		`<p>Quickstart: ${a(QUICKSTART)}</p>`,
		`<p>Questions? Reply to this email or write to <a href="mailto:${SUPPORT}">${SUPPORT}</a>.</p>`,
	].join("\n");

	return { subject: SUBJECT, text, html };
}

// Per-isolate state. Workspace creation is rare, so the set stays tiny; the cap
// only guards a long-lived isolate.
const handled = new Set<string>();
const HANDLED_CAP = 1000;
let warnedUnconfigured = false;

/** Test seam: reset the per-isolate state. Not used by production code. */
export function resetWelcomeEmailStateForTests(): void {
	handled.clear();
	warnedUnconfigured = false;
}

/** A session email is trusted, but it still goes into a JSON `to` field:
 *  reject anything that is not a single plain address. */
function plausibleAddress(s: string): boolean {
	return /^[^\s,;<>"]+@[^\s,;<>"]+$/.test(s);
}

/**
 * Send the welcome email. Resolves, never rejects. Logs carry the org id and
 * an HTTP status, never the recipient address or a response body.
 */
export async function sendWelcomeEmail(
	input: WelcomeEmailInput,
): Promise<WelcomeResult> {
	try {
		const key = process.env.RESEND_API_KEY;
		const from = process.env.RESEND_FROM;
		if (!key || !from) {
			// Degraded state entered: ONE line per isolate, not per signup
			// (`.claude/rules/logging.md`). No sender address is invented — an
			// unverified one would turn every send into a 403.
			if (!warnedUnconfigured) {
				warnedUnconfigured = true;
				console.warn(
					JSON.stringify({
						event: "welcome_email_skipped",
						marker: "TRACELANE_DEGRADED email_unconfigured",
						reason: key ? "RESEND_FROM unset" : "RESEND_API_KEY unset",
					}),
				);
			}
			return "skipped";
		}
		if (!plausibleAddress(input.to)) {
			console.warn(
				JSON.stringify({
					event: "welcome_email_skipped",
					marker: "TRACELANE_DEGRADED email_unconfigured",
					reason: "recipient not a plain address",
					workspace: input.workspaceId,
				}),
			);
			return "skipped";
		}
		if (handled.has(input.workspaceId)) return "duplicate";
		if (handled.size >= HANDLED_CAP) handled.clear();
		handled.add(input.workspaceId);

		const { subject, text, html } = buildWelcomeEmail(input.workspaceName);
		const ok = await sendEmail({
			to: input.to,
			from,
			replyTo: SUPPORT,
			subject,
			text,
			html,
			idempotencyKey: `welcome-${input.workspaceId}`,
		});
		if (!ok) {
			// `sendEmail` has already logged the status; this line names the event
			// so a `welcome_email_failed` search finds it.
			console.error(
				JSON.stringify({
					event: "welcome_email_failed",
					workspace: input.workspaceId,
				}),
			);
			return "failed";
		}
		return "sent";
	} catch (err) {
		console.error(
			JSON.stringify({
				event: "welcome_email_failed",
				workspace: input.workspaceId,
				error: err instanceof Error ? err.name : "unknown",
			}),
		);
		return "failed";
	}
}

/**
 * Schedule the send to run AFTER the response. On the Worker, `after()` is
 * backed by the request's `waitUntil` (OpenNext forwards it to Next's request
 * context), so the isolate is kept alive until the send settles. Outside a
 * request scope `after()` throws; fall back to a detached promise rather than
 * lose the send. Never throws.
 */
export function scheduleWelcomeEmail(input: WelcomeEmailInput): void {
	try {
		after(() => sendWelcomeEmail(input));
	} catch {
		void sendWelcomeEmail(input);
	}
}
