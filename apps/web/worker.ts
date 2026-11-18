/**
 * Custom Worker entry (OpenNext "custom worker"): the app's `fetch` handler, unchanged, plus
 * the daily cron. `wrangler.jsonc` points `main` here; the crons are in `triggers.crons`.
 *
 * Excluded from `tsc` (tsconfig.json) because `.open-next/worker.js` exists only after
 * `opennextjs-cloudflare build`; the logic it calls lives in `lib/usage-digest.ts`, which IS
 * type-checked and tested.
 */
import { default as handler } from "./.open-next/worker.js";
import { runUsageDigest } from "./lib/usage-digest";

// Re-exported as OpenNext's own entry does, so binding them later needs no change here.
export {
	BucketCachePurge,
	DOQueueHandler,
	DOShardedTagCache,
} from "./.open-next/worker.js";

export default {
	fetch: handler.fetch,
	async scheduled(
		event: { scheduledTime: number },
		env: Record<string, unknown>,
		ctx: { waitUntil(p: Promise<unknown>): void },
	) {
		ctx.waitUntil(runUsageDigest(new Date(event.scheduledTime), { env }));
	},
};
