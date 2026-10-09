"use client";
import type { SpanUsage } from "./types";

/** The gateway supplies the arithmetic and prices; this panel only labels it. */
export function UsagePanel({ usage }: { usage: SpanUsage | undefined }) {
	if (!usage) return null;
	const rows = [
		[
			"Uncached input",
			usage.buckets?.uncached_input,
			usage.bucket_cost_usd?.uncached_input,
		],
		[
			"Cache read",
			usage.cache_read_tokens === null ? undefined : usage.buckets?.cache_read,
			usage.cache_read_tokens === null
				? undefined
				: usage.bucket_cost_usd?.cache_read,
		],
		[
			"Cache write",
			usage.cache_write_tokens === null
				? undefined
				: usage.buckets?.cache_write,
			usage.cache_write_tokens === null
				? undefined
				: usage.bucket_cost_usd?.cache_write,
		],
		[
			"Reasoning",
			usage.reasoning_tokens === null ? undefined : usage.buckets?.reasoning,
			usage.reasoning_tokens === null
				? undefined
				: usage.bucket_cost_usd?.reasoning,
		],
		[
			usage.reasoning_tokens === null
				? "Output (incl. any reasoning)"
				: "Output (excl. reasoning)",
			usage.buckets?.output,
			usage.bucket_cost_usd?.output,
		],
	] as const;
	const totalKnown =
		usage.buckets !== null &&
		usage.cache_read_tokens !== null &&
		usage.cache_write_tokens !== null &&
		usage.reasoning_tokens !== null;
	return (
		<section
			className="rounded-card border border-line bg-surface-2 p-3"
			aria-label="Token usage and cost"
		>
			<h3 className="mb-2 t-metric-label">Token usage and cost</h3>
			{usage.estimated && (
				<p className="mb-2 text-xs text-warn-ink">Estimated token counts</p>
			)}
			{usage.convention === "unknown" && (
				<p className="mb-2 text-xs text-ink-2">
					As reported by the provider — Tracelane cannot tell whether input
					includes cache reads. No split or per-bucket cost is shown.
				</p>
			)}
			{usage.convention !== "unknown" && !usage.buckets && (
				<p className="mb-2 text-xs text-ink-2">
					Counts are inconsistent; raw values are shown as reported by the
					provider.
				</p>
			)}
			{usage.buckets ? (
				<dl className="space-y-1 text-xs">
					{rows.map(([label, count, cost]) => (
						<div
							key={label}
							className="flex items-baseline justify-between gap-3"
						>
							<dt className="text-ink-3">{label}</dt>
							<dd className="text-right font-mono tabular-nums text-ink">
								{count === undefined ? "not reported" : count.toLocaleString()}
								{cost !== undefined ? ` · $${cost.toFixed(6)}` : ""}
							</dd>
						</div>
					))}
					{totalKnown && (
						<div className="flex justify-between border-t border-line pt-1">
							<dt className="text-ink-3">Billed tokens</dt>
							<dd className="font-mono tabular-nums text-ink">
								{usage.billed_tokens?.toLocaleString() ?? "—"}
							</dd>
						</div>
					)}
				</dl>
			) : (
				<dl className="space-y-1 text-xs">
					{[
						["Input as reported", usage.input_tokens],
						["Output as reported", usage.output_tokens],
						["Cache read as reported", usage.cache_read_tokens],
						["Cache write as reported", usage.cache_write_tokens],
					].map(([label, n]) => (
						<div className="flex justify-between gap-3" key={String(label)}>
							<dt className="text-ink-3">{label}</dt>
							<dd className="font-mono text-ink">
								{typeof n === "number" ? n.toLocaleString() : "not reported"}
							</dd>
						</div>
					))}
				</dl>
			)}
			<div className="mt-2 border-t border-line pt-2 text-xs text-ink-2">
				<p>
					Total cost:{" "}
					<span className="font-mono">
						{usage.cost_usd === null ? "—" : `$${usage.cost_usd.toFixed(6)}`}
					</span>
				</p>
				<p>
					{usage.cost_origin === "computed"
						? "Computed from the price catalog"
						: usage.cost_origin === "provider_reported"
							? "Cost as reported by the provider"
							: usage.cost_origin === "unpriced"
								? "No price recorded for this model"
								: "Cost origin not recorded"}
				</p>
			</div>
		</section>
	);
}
