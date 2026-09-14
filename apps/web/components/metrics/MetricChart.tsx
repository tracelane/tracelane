"use client";

/**
 * MetricChart — the app's binding of `TimeSeriesChart` to Next and to the
 * registry (DSH-11 §3b). The package cannot import `next/navigation` or the
 * app's formatters, so this ~40-line wrapper is where soft navigation, the ONE
 * formatter per kind, the bucket click-through and brush-to-zoom URL rewrite
 * are injected. Every windowed chart on every page renders through it.
 */

import { fmtByKind } from "@/lib/metrics/format";
import type { ChartData } from "@/lib/metrics/series";
import { bucketHref, withWindow } from "@/lib/metrics/time-range";
import { TimeSeriesChart } from "@tracelanedev/ui";
import { usePathname, useRouter } from "next/navigation";

export function MetricChart({
	data,
	label,
	height,
	/** Drill-through target for a bucket; omit for a chart with no click-through. */
	drillPath,
	/** Extra params for the drill-through (model, status, signature_id…). */
	drillParams,
	/** Brush-to-zoom rewrites THIS page's window. Default on. */
	brush = true,
	legend,
	className,
}: {
	data: ChartData;
	label: string;
	height?: number;
	drillPath?: string;
	drillParams?: Record<string, string | undefined>;
	brush?: boolean;
	legend?: boolean;
	className?: string;
}) {
	const router = useRouter();
	const pathname = usePathname();
	return (
		<TimeSeriesChart
			buckets={data.buckets}
			series={data.series}
			n={data.n}
			label={label}
			height={height}
			legend={legend}
			className={className}
			format={fmtByKind}
			onNavigate={(href) => router.push(href)}
			hrefFor={
				drillPath
					? (i) => {
							const b = data.buckets[i];
							return b ? bucketHref(drillPath, b, drillParams) : undefined;
						}
					: undefined
			}
			onBrush={
				brush
					? (sinceMs, untilMs) =>
							router.push(
								withWindow(pathname, {
									kind: "custom",
									preset: null,
									sinceMs,
									untilMs,
								}),
							)
					: undefined
			}
		/>
	);
}
