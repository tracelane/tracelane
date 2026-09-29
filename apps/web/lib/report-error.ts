/**
 * Client error reporting (2026-09-27, launch readiness) — every crash a person hits in the
 * browser leaves ONE structured line in the Worker's logs, so we learn about it from the
 * log and not from the person. No third-party SDK: `/api/client-errors` writes a tagged
 * JSON line (`"tl":"client-error"`) that `scripts/ops/web-errors.sh` counts.
 *
 * Bounded on purpose: at most MAX_PER_PAGE reports per page load and each distinct
 * message once, so a render loop cannot flood the log. Never throws — reporting an error
 * must not become a second error.
 */

export type ClientErrorKind = "boundary" | "global" | "window" | "rejection";

const MAX_PER_PAGE = 10;
let sent = 0;
const seen = new Set<string>();

function text(v: unknown, max: number): string {
	const s =
		typeof v === "string"
			? v
			: v instanceof Error
				? v.message
				: String(v ?? "");
	return s.slice(0, max);
}

export function reportClientError(
	err: unknown,
	kind: ClientErrorKind,
	digest?: string,
): void {
	try {
		if (typeof window === "undefined" || sent >= MAX_PER_PAGE) return;
		const message = text(err, 500);
		const key = `${kind}|${message}`;
		if (seen.has(key)) return;
		seen.add(key);
		sent++;
		const stack =
			err instanceof Error && err.stack
				? err.stack.split("\n").slice(0, 8).join("\n").slice(0, 2000)
				: undefined;
		const body = JSON.stringify({
			kind,
			message,
			stack,
			digest: digest?.slice(0, 64),
			// Path only — a query string can carry ids a person typed.
			path: window.location.pathname.slice(0, 300),
		});
		const blob = new Blob([body], { type: "application/json" });
		if (!navigator.sendBeacon?.("/api/client-errors", blob)) {
			// client-bare-fetch-ok: a beacon must never navigate away from the page it reports on.
			void fetch("/api/client-errors", {
				method: "POST",
				body,
				keepalive: true,
			}).catch(() => {});
		}
	} catch {
		// Reporting must never throw.
	}
}
