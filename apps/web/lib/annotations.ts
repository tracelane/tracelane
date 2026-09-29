/**
 * `OBS-56` slice 3 — the bulk-select action bar's client helper for the batch
 * trace-level flag. The gateway proxy at `/api/traces/annotations/batch` owns
 * tenant resolution, the role gate and the `bulk_trace_action_max` cap; this
 * is only the one place that spells the route + method, so the bar's
 * Flag button has a single call to make. `check-unreachable-write-routes.py`
 * cannot see a caller under `apps/web/lib/` (its corpus is `app/**` +
 * `components/**` only) — allowlisted as `in-app-wrapper`, evidence this file.
 */

import { apiFetch } from "@/lib/api-fetch";

export type BatchAnnotationLabel = "good" | "bad" | "needs_review";

export type BatchAnnotationResult = {
	written: number;
	refused: { trace_id: string; reason: string }[];
};

/** Flag every id in `traceIds` with `label` (+ an optional shared note), as one call. */
export async function flagTracesBatch(
	traceIds: string[],
	label: BatchAnnotationLabel,
	note?: string,
): Promise<BatchAnnotationResult> {
	return apiFetch<BatchAnnotationResult>("/api/traces/annotations/batch", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			trace_ids: traceIds,
			label,
			...(note ? { note } : {}),
		}),
	});
}
