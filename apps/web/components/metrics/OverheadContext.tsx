import { fmtDurationMs } from "@/lib/metrics/format";
type Split = {
	overhead_samples: number;
	warm_samples?: number;
	cold_start_samples?: number;
	overhead_warm_p50_ms?: number;
	overhead_warm_p95_ms?: number;
	cache_hit_samples?: number;
	cache_hit_served_p50_ms?: number;
	cache_hit_served_p95_ms?: number;
};
export function OverheadContext({ data }: { data?: Split | null }) {
	const time = (n: number | undefined, samples: number) =>
		samples > 0 && n !== undefined
			? n === 0
				? "0 ms"
				: fmtDurationMs(n)
			: "—";
	return (
		<div
			aria-label="Gateway overhead context"
			className="mt-4 rounded-card border border-line bg-surface-2 p-3 text-xs text-ink-2"
		>
			<div className="flex flex-wrap gap-x-6 gap-y-2">
				{data?.warm_samples !== undefined && (
					<p>
						Steady state p50{" "}
						{time(data.overhead_warm_p50_ms, data.warm_samples)} · p95{" "}
						{time(data.overhead_warm_p95_ms, data.warm_samples)} · n ={" "}
						{data.warm_samples}
					</p>
				)}
				{data?.cold_start_samples !== undefined && (
					<p>
						{data.cold_start_samples} of {data.overhead_samples} requests paid a
						cold start
					</p>
				)}
				{!!data?.cache_hit_samples && (
					<p>
						Served from cache · p50{" "}
						{time(data.cache_hit_served_p50_ms, data.cache_hit_samples)} · p95{" "}
						{time(data.cache_hit_served_p95_ms, data.cache_hit_samples)} · n ={" "}
						{data.cache_hit_samples} (excluded from gateway and provider
						overhead)
					</p>
				)}
			</div>
			<p className="mt-2 border-t border-line pt-2">
				{data?.cache_hit_samples !== undefined &&
					"Gateway overhead excludes response cache hits. "}
				Measured on your real requests. It includes authenticating your key and
				loading your workspace settings, which can take hundreds of milliseconds
				after an idle period. Tracelane's published 2 / 4 / 5 ms is a warm load
				benchmark against a mock provider.
			</p>
		</div>
	);
}
