import { createHash } from "node:crypto";
import { db } from "@/db";
import { sql } from "drizzle-orm";

/**
 * Shared fixed-window counter; database time is authoritative across isolates.
 *
 * @throws Error("rate_limit_unavailable") when the counter cannot be read or written.
 *   Fail-CLOSED: every caller must refuse the request (503), never allow it.
 */
export async function rateLimit(
	key: string,
	limit: number,
	windowMs: number,
): Promise<boolean> {
	const hash = createHash("sha256").update(key).digest("hex");
	try {
		const result = await db.execute<{ count: number }>(sql`
            INSERT INTO web_rate_limits (key_hash, window_start, count)
            VALUES (decode(${hash}, 'hex'),
                to_timestamp(floor(extract(epoch FROM now()) * 1000 / ${windowMs}::bigint)
                    * ${windowMs}::bigint / 1000), 1)
            ON CONFLICT (key_hash, window_start)
            DO UPDATE SET count = web_rate_limits.count + 1
            RETURNING count
        `);
		const count = result.rows[0]?.count;
		if (typeof count !== "number" || !Number.isInteger(count) || count < 1) {
			throw new Error("invalid counter result");
		}
		if (Math.random() < 0.01) {
			// Housekeeping only: this request is already counted and decided, so a failed
			// DELETE is logged and never turns an allowed request into a 503.
			try {
				await db.execute(sql`
                    DELETE FROM web_rate_limits
                    WHERE window_start < now() - interval '1 day'
                `);
			} catch {
				console.error("rate_limit_cleanup_failed");
			}
		}
		return count <= limit;
	} catch {
		// Fixed text only: no database error and no caller identifier reaches a log or a response.
		console.error("rate_limit_unavailable");
		throw new Error("rate_limit_unavailable");
	}
}

/** Best-effort client IP from the standard proxy headers (CF / Vercel). */
export function clientIp(headers: Headers): string {
	return (
		headers.get("cf-connecting-ip") ??
		headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
		"unknown"
	);
}
