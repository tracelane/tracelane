/**
 * In-memory fixed-window rate limiter for auth-adjacent web routes
 * side (the gateway has its own for WorkOS webhooks).
 *
 * ponytail: per-instance, not global. On serverless (CF Workers) each isolate
 * keeps its own counters, so this throttles a warm-isolate burst but is NOT a
 * hard global cap — a distributed attacker across isolates can exceed it. The
 * hard bound on invite abuse is the seat cap (pending invites count toward it,
 * and invite is owner-only). Upgrade to a KV / Durable-Object / Postgres
 * counter if a strict global limit is ever required.
 */

type Window = { count: number; resetAt: number };

const windows = new Map<string, Window>();

/**
 * Returns `true` if the call is allowed, `false` if the key has exhausted its
 * `limit` within the current `windowMs`. Fixed-window (not sliding) — cheap and
 * good enough for burst suppression.
 */
export function rateLimit(
	key: string,
	limit: number,
	windowMs: number,
): boolean {
	const now = Date.now();
	const w = windows.get(key);
	if (!w || now >= w.resetAt) {
		windows.set(key, { count: 1, resetAt: now + windowMs });
		return true;
	}
	if (w.count >= limit) return false;
	w.count += 1;
	return true;
}

/** Best-effort client IP from the standard proxy headers (CF / Vercel). */
export function clientIp(headers: Headers): string {
	return (
		headers.get("cf-connecting-ip") ??
		headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
		"unknown"
	);
}
