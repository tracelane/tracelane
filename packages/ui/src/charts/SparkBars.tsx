import { cn } from "../lib/cn";

/**
 * SparkBars — a micro bar series: the SHAPE of a metric over its buckets, small
 * enough to sit inside a tile beside the number.
 *
 * DELIBERATELY NOT A SPARKLINE. The data are buckets, and a line across buckets
 * draws values between them that were never measured — the same reason `BarChart`
 * exists as discrete marks. A dashboard whose whole claim is full-fidelity capture
 * cannot interpolate on its own front page.
 *
 * EXTRACTED FROM `StatCard` (DSH-08). It lived as a private `Spark` inside that
 * file, so the moment a second surface wanted the same 12px shape — the dashboard's
 * error-rate strip — the choice was a sixth reimplementation or an export. This is
 * the same reasoning `StatGrid`'s header records about the metric ROW: the tiles
 * were shared, the layout was not, and the surfaces stopped reading as one system.
 *
 * COLOUR (P0.11, 2026-08-22). `fill-chart-secondary`, flat — NOT `chart-primary` at a
 * low opacity, and the choice was made on composited values rather than by taste.
 * `fill-ink-3 opacity-55` stood here, and an alpha always moves a mark TOWARD its
 * background, so the pair drifted apart across the two themes: composited it is ~#bababa
 * on the #ffffff card (a separation of ~69/255) and ~#48484e on the #151619 one (~51).
 * `--chart-secondary` is a real per-theme value — #a7a7a7 light, #777777 dark — landing
 * at ~88 and ~98 of separation, so the spark reads a little stronger AND more evenly at
 * both ends, with one number to tune instead of a token-plus-alpha pair.
 * It is also the token that NAMES this mark: a de-emphasised data mark.
 *
 * The inverse branch keeps `fill-ink-inverse opacity-45` on purpose — `--surface-inverse`
 * is dark in BOTH themes, so an ink-inverse wash is already theme-stable there and
 * chart-secondary would go dim against it in dark.
 *
 * HONEST BY CONSTRUCTION:
 *  - fewer than two values renders NOTHING, never a flat line — one point is not a
 *    trend, and a flat line claims measured zeros we did not measure;
 *  - an all-zero series renders zero-height bars, which is the true shape;
 *  - values are normalised against the series max, so the shape is relative and the
 *    component makes no claim about absolute magnitude. The number beside it does.
 */
export interface SparkBarsProps {
	/** Raw bucket values — normalised internally. */
	values: readonly number[];
	/** Render on a `--surface-inverse` card. */
	inverse?: boolean;
	/** Bar height in px. */
	height?: number;
	/**
	 * Accessible name. Omit for a decorative spark that a sibling number already
	 * names (the StatCard case); supply it when the spark is the only description
	 * of the series (the dashboard KPI strip).
	 */
	ariaLabel?: string;
	className?: string;
}

export function SparkBars({
	values,
	inverse,
	height = 12,
	ariaLabel,
	className,
}: SparkBarsProps) {
	if (values.length < 2) return null;
	const max = Math.max(...values, 0) || 1;
	const n = values.length;
	return (
		<svg
			viewBox={`0 0 ${n * 3} ${height}`}
			height={height}
			width="100%"
			preserveAspectRatio="none"
			role={ariaLabel ? "img" : undefined}
			aria-label={ariaLabel}
			aria-hidden={ariaLabel ? undefined : "true"}
			className={cn("block max-w-[112px]", className)}
		>
			{values.map((v, i) => {
				const h = Math.max((v / max) * height, v > 0 ? 1 : 0);
				return (
					<rect
						key={`${i}:${v}`}
						x={i * 3}
						y={height - h}
						width={2}
						height={h}
						className={
							inverse ? "fill-ink-inverse opacity-45" : "fill-chart-secondary"
						}
					/>
				);
			})}
		</svg>
	);
}
