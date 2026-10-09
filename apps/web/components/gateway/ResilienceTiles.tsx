"use client";
import { ApiError, apiFetch } from "@/lib/api-fetch";
import type { GatewayStats } from "@/lib/gateway-ops";
import { fmtCount } from "@/lib/metrics/format";
import { METRICS } from "@/lib/metrics/registry";
import { Button, StatCard } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
export type ResilienceStats = Pick<
	GatewayStats,
	| "agent_loops"
	| "requests_with_failed_attempt"
	| "rescued_by_failover"
	| "rescued_by_retry"
	| "rescue_rate_pct"
	| "rescue_added_ms_p50"
	| "attempt_records_since"
>;
export function ResilienceTiles({
	initial,
	query,
}: { initial: ResilienceStats | null; query: string }) {
	const [data, setData] = useState(initial);
	const [error, setError] = useState<unknown>(null);
	const [loading, setLoading] = useState(false);
	useEffect(() => {
		setData(initial);
		setError(null);
	}, [initial]);
	async function retry() {
		setLoading(true);
		setError(null);
		try {
			setData(await apiFetch<GatewayStats>(`/api/gateway/stats?${query}`));
		} catch (e) {
			setError(e);
		} finally {
			setLoading(false);
		}
	}
	const failure = (
		<div role="alert" className="text-sm">
			{error instanceof ApiError && error.status === 403 ? (
				"You don't have access to traces in this workspace"
			) : (
				<>
					Couldn't load — your traces are unaffected.{" "}
					<Button
						variant="secondary"
						size="sm"
						onClick={retry}
						disabled={loading}
					>
						{loading ? "Loading…" : "Retry"}
					</Button>
				</>
			)}
		</div>
	);
	const link = (key: string, value: string) =>
		`/traces?${query}&${key}=${value}`;
	const loops = data?.agent_loops;
	const failed = data?.requests_with_failed_attempt;
	return (
		<section aria-label="Agent loops and request rescues" className="space-y-3">
			<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
				<a href={link("loop", "true")}>
					<StatCard
						label={METRICS.agent_loops.label}
						value={loops ? fmtCount(loops.instances) : "—"}
						hint={
							loops?.min_repeats && loops.window_secs
								? `${loops.min_repeats}+ identical calls within ${loops.window_secs / 60} min. Calls beyond the 32 stored tool calls per response cannot be compared.`
								: "Repeated tool and argument fingerprints within a session or trace."
						}
					/>
				</a>
				<a href={link("rescued", "failover")}>
					<StatCard
						label={METRICS.rescued_failover.label}
						value={fmtCount(data?.rescued_by_failover)}
					/>
				</a>
				<a href={link("rescued", "retry")}>
					<StatCard
						label={METRICS.rescued_retry.label}
						value={fmtCount(data?.rescued_by_retry)}
					/>
				</a>
				<a href={link("rescued", "any")}>
					<StatCard
						label={METRICS.rescue_rate.label}
						value={
							data?.rescue_rate_pct == null
								? "—"
								: `${data.rescue_rate_pct.toFixed(1)}%`
						}
						hint="Of requests that hit a provider failure, the share we still answered."
					/>
				</a>
				<a href={link("rescued", "any")}>
					<StatCard
						label={METRICS.rescue_latency.label}
						value={
							data?.rescue_added_ms_p50 == null
								? "—"
								: `${data.rescue_added_ms_p50.toFixed(1)} ms`
						}
						hint="Median time spent in failed provider attempts before a successful dispatch."
					/>
				</a>
			</div>
			{!loops ? (
				failure
			) : (
				<p className="mt-2 text-xs text-ink-3">
					{loops.tool_calls === 0
						? "No tool calls in this range."
						: loops.instances === 0
							? "0 loops detected"
							: `in ${loops.groups} sessions/traces`}
					{loops.unfingerprinted_tool_calls > 0 &&
						` · ${loops.unfingerprinted_tool_calls} tool calls couldn't be compared — sent before this feature, or through a path without a fingerprint key.`}
				</p>
			)}
			{failed == null ? (
				failure
			) : failed === 0 ? (
				<p className="text-sm text-ink-3">
					No provider failures in this range — nothing needed rescuing
				</p>
			) : (data?.rescued_by_failover ?? 0) + (data?.rescued_by_retry ?? 0) ===
				0 ? (
				<a className="text-sm underline" href={link("has_error", "true")}>
					0 of {failed} failed requests were rescued
				</a>
			) : null}
			{data?.attempt_records_since && (
				<p className="text-xs text-ink-3">
					Based on attempt records since {data.attempt_records_since}.
				</p>
			)}
		</section>
	);
}
