/**
 * `EVL-03` §2/§5 — `billing_policy.playground_limits`, the ONE reference table
 * for every playground cap, window and poll interval (CLAUDE.md §23). Exact
 * shape of `apps/web/lib/list-page-settings.ts`: a reviewed JSON fallback,
 * read through Next's shared data cache on the existing control-plane
 * cadence, never a literal in the route or the form.
 */
import { db } from "@/db";
import reference from "@/db/plans.v3.json";
import { billingPolicy } from "@/db/schema";
import { orgArchivedCacheTtlMs } from "@/lib/auth";
import { eq } from "drizzle-orm";
import { unstable_cache } from "next/cache";

export type PlaygroundLimits = typeof reference.policy.playground_limits;
export type PlaygroundSettings = {
	limits: PlaygroundLimits;
	defaulted: boolean;
};

const NUMERIC_KEYS = [
	"max_columns",
	"max_messages",
	"max_body_bytes",
	"max_tokens_cap",
	"timeout_ms",
	"cost_poll_seconds",
	"history_entries",
] as const satisfies readonly (keyof PlaygroundLimits)[];

const fallback = (): PlaygroundSettings => ({
	limits: reference.policy.playground_limits,
	defaulted: true,
});

async function readSettings(): Promise<PlaygroundSettings> {
	try {
		const [row] = await db
			.select({ value: billingPolicy.value })
			.from(billingPolicy)
			.where(eq(billingPolicy.key, "playground_limits"))
			.limit(1);
		const value = row?.value as Partial<PlaygroundLimits> | undefined;
		if (
			!value ||
			!NUMERIC_KEYS.every((key) => {
				const n = value[key];
				return typeof n === "number" && Number.isSafeInteger(n) && n > 0;
			})
		)
			return fallback();
		return { limits: value as PlaygroundLimits, defaulted: false };
	} catch {
		return fallback();
	} // Display/enforcement settings fail open to the reviewed JSON default.
}

/** Next's shared data cache, on the existing web control-plane cadence. No
 * session data enters this global reference read; gateway authorization still
 * determines what the caller may run. Failures are cached too, avoiding a
 * database retry on every playground request during an outage. */
export async function getPlaygroundSettings(): Promise<PlaygroundSettings> {
	try {
		return await unstable_cache(readSettings, ["playground-limits-v1"], {
			revalidate: Math.max(1, Math.floor(orgArchivedCacheTtlMs() / 1000)),
		})();
	} catch {
		return fallback();
	}
}
