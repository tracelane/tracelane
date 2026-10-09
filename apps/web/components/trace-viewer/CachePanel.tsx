"use client";

import { apiFetchRaw } from "@/lib/api-fetch";
import { fmtUsd } from "@/lib/metrics/format";
import { isTraceId } from "@/lib/trace-id";
import { useEffect, useState } from "react";

/** Tracelane response-cache evidence, separate from provider prompt-cache tokens. */
export function CachePanel({
	attrs,
	enabled,
}: { attrs: Record<string, unknown>; enabled: boolean }) {
	const hit = attrs.tracelane_semantic_cache_hit;
	const tier = attrs.tracelane_semantic_cache_tier;
	const source = isTraceId(attrs.tracelane_semantic_cache_source_trace_id)
		? attrs.tracelane_semantic_cache_source_trace_id
		: undefined;
	const [sourceState, setSourceState] = useState<
		"unknown" | "checking" | "retained" | "missing"
	>("unknown");
	useEffect(() => {
		if (hit !== true || !source) return;
		const controller = new AbortController();
		setSourceState("checking");
		apiFetchRaw(`/api/traces/${encodeURIComponent(source)}/spans`, {
			signal: controller.signal,
		})
			.then((res) =>
				setSourceState(
					res.status === 404 ? "missing" : res.ok ? "retained" : "unknown",
				),
			)
			.catch(() => {
				if (!controller.signal.aborted) setSourceState("unknown");
			});
		return () => controller.abort();
	}, [hit, source]);
	if (!enabled) return null;
	const similarity =
		typeof attrs.tracelane_semantic_cache_similarity === "number"
			? attrs.tracelane_semantic_cache_similarity
			: undefined;
	const saved =
		typeof attrs.tracelane_semantic_cache_cost_saved_usd === "number"
			? attrs.tracelane_semantic_cache_cost_saved_usd
			: undefined;
	return (
		<section
			className="rounded-card border border-line bg-surface-2 p-3"
			aria-label="Tracelane response cache"
		>
			<h3 className="mb-2 t-metric-label">Tracelane response cache</h3>
			<p className="text-xs text-ink">
				{hit === true
					? "Served from cache"
					: hit === false
						? "Consulted — miss"
						: "Response cache not enabled for this request"}
			</p>
			{hit === true && (
				<>
					{typeof tier === "string" && (
						<p className="mt-1 text-xs text-ink-2">Tier: {tier}</p>
					)}
					{tier === "semantic" && similarity !== undefined && (
						<p className="mt-1 text-xs text-ink-2">
							Similarity: {similarity.toFixed(2)}
						</p>
					)}
					{source &&
						(sourceState === "missing" ? (
							<p className="mt-1 text-xs text-ink-3">
								source trace no longer retained
							</p>
						) : (
							<p className="mt-1 text-xs">
								<a
									className="text-action-ink underline"
									href={`/traces/${encodeURIComponent(source)}`}
								>
									Source trace
								</a>
								{sourceState === "checking" && (
									<span className="text-ink-3"> · checking retention</span>
								)}
							</p>
						))}
					<p className="mt-1 text-xs text-ink-2">
						{saved === undefined
							? "saving not recorded"
							: `Saved ${fmtUsd(saved)} (what the original call cost)`}
					</p>
				</>
			)}
		</section>
	);
}
