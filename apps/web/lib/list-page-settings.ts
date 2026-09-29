import { db } from "@/db";
import reference from "@/db/plans.v3.json";
import { billingPolicy } from "@/db/schema";
import { orgArchivedCacheTtlMs } from "@/lib/auth";
import { eq } from "drizzle-orm";
import { unstable_cache } from "next/cache";
export type ListPageSizes = typeof reference.policy.web_list_page_sizes;
export type ListPageSettings = { sizes: ListPageSizes; defaulted: boolean };
const fallback = (): ListPageSettings => ({
	sizes: reference.policy.web_list_page_sizes,
	defaulted: true,
});
async function readSettings(): Promise<ListPageSettings> {
	try {
		const [row] = await db
			.select({ value: billingPolicy.value })
			.from(billingPolicy)
			.where(eq(billingPolicy.key, "web_list_page_sizes"))
			.limit(1);
		const value = row?.value as Partial<ListPageSizes> | undefined;
		if (
			!value ||
			!Object.keys(reference.policy.web_list_page_sizes).every((key) => {
				const n = value[key as keyof ListPageSizes];
				return typeof n === "number" && Number.isSafeInteger(n) && n > 0;
			})
		)
			return fallback();
		return { sizes: value as ListPageSizes, defaulted: false };
	} catch {
		return fallback();
	} // Display settings fail open; the pages disclose the reviewed defaults.
}
/** Next's shared data cache, on the existing web control-plane cadence.
 * No session data enters this global reference read; gateway authorization still
 * determines which rows the caller can see. Failures are cached too, avoiding a
 * database retry on every page view during an outage. */
export async function getListPageSettings(): Promise<ListPageSettings> {
	try {
		return await unstable_cache(readSettings, ["web-list-page-sizes-v1"], {
			revalidate: Math.max(1, Math.floor(orgArchivedCacheTtlMs() / 1000)),
		})();
	} catch {
		return fallback();
	}
}

/**
 * OBS-56 — the trace-list bulk-select cap. Display only: the number here
 * disclosed to the UI (checkbox refusal past it, "Up to N at once") and the
 * gateway's OWN read of the same `billing_policy` row is what actually
 * enforces it on the batch write path (fail-closed there; fail-open here,
 * same "display vs security" split as `getListPageSettings`).
 */
export type BulkSettings = { max: number; defaulted: boolean };
const bulkFallback = (): BulkSettings => ({
	max: reference.policy.bulk_trace_action_max,
	defaulted: true,
});
async function readBulkSettings(): Promise<BulkSettings> {
	try {
		const [row] = await db
			.select({ value: billingPolicy.value })
			.from(billingPolicy)
			.where(eq(billingPolicy.key, "bulk_trace_action_max"))
			.limit(1);
		const value = row?.value;
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0)
			return bulkFallback();
		return { max: value, defaulted: false };
	} catch {
		return bulkFallback();
	}
}
export async function getBulkSettings(): Promise<BulkSettings> {
	try {
		return await unstable_cache(
			readBulkSettings,
			["bulk-trace-action-max-v1"],
			{
				revalidate: Math.max(1, Math.floor(orgArchivedCacheTtlMs() / 1000)),
			},
		)();
	} catch {
		return bulkFallback();
	}
}
