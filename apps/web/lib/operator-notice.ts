/**
 * operator-notice.ts — helpers for the plain notices sent to the operator inbox (the signup
 * alert and the daily usage digest). Dependency-free on purpose: the Worker's cron entry
 * (`worker.ts`) bundles this file outside the Next.js build.
 */

/** Neutralise user-supplied text for an operator notice: control, format (bidi, zero-width)
 *  and line/paragraph separators become spaces, whitespace collapses, and the result is
 *  capped with an ellipsis. */
export function sanitizeUserText(s: string, max = 100): string {
	const flat = s
		.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, " ")
		.replace(/\s+/g, " ")
		.trim();
	const chars = Array.from(flat);
	return chars.length > max ? `${chars.slice(0, max).join("")}…` : flat;
}

/** One plain address: no display name, no list, no whitespace. */
export function plainAddress(s: string): boolean {
	return /^[^\s,;<>"@]+@[^\s,;<>"@]+$/.test(s);
}

// founder, 2026-09-30: founder@tracelane.dev is the operator inbox (welcome-email.ts SUPPORT).
export const OPERATOR_INBOX = "founder@tracelane.dev";
