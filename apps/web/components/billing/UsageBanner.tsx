/**
 * UsageBanner — the three banner variants on `/settings/billing` (spec §8):
 * warn (75%+), danger (90%+), and the ceiling-reached/auto-age-acted
 * resolved variant.
 *
 * Wireframe review note: the "nothing was lost" badge is NEUTRAL tone, never
 * `ok` (green) — a green pill on a billing-limit event reads as a reward for
 * hitting a ceiling, which is the wrong signal for what is, functionally, a
 * customer running low on headroom.
 */

import { Badge } from "@tracelanedev/ui";

export function WarnBanner({
	meterLabel,
	pct,
	projectionText,
	overageUsd,
	rateText,
	danger,
	onOpenBreakdown,
	onOpenCeiling,
	ceilingUsd,
}: {
	meterLabel: string;
	pct: number;
	projectionText: string;
	overageUsd: number | null;
	rateText: string | null;
	danger: boolean;
	onOpenBreakdown: () => void;
	onOpenCeiling: () => void;
	ceilingUsd: number | null;
}) {
	const tone = danger ? "danger" : "warn";
	return (
		<div
			className={
				danger
					? "flex flex-wrap items-center justify-between gap-3 rounded-[var(--radius-card)] border border-danger/30 bg-danger-soft px-4 py-3"
					: "flex flex-wrap items-center justify-between gap-3 rounded-[var(--radius-card)] border border-warn/30 bg-warn-soft px-4 py-3"
			}
		>
			<p
				className={`text-sm font-medium ${danger ? "text-danger-ink" : "text-warn-ink"}`}
			>
				⚠ {meterLabel} is at {pct}% — {projectionText}
				{overageUsd !== null && overageUsd > 0 && rateText ? (
					<>
						{" "}
						Overage ${overageUsd.toFixed(2)} at {rateText}.
					</>
				) : null}
			</p>
			<div className="flex flex-wrap items-center gap-3">
				<button
					type="button"
					onClick={onOpenBreakdown}
					className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
				>
					What&apos;s using your window ▸
				</button>
				<span className="flex items-center gap-2 text-xs text-ink-2">
					Spend ceiling: {ceilingUsd === null ? "OFF" : `$${ceilingUsd}`}
					<button
						type="button"
						onClick={onOpenCeiling}
						className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
					>
						{ceilingUsd === null ? "Set a ceiling" : "Edit ceiling"}
					</button>
				</span>
			</div>
			<Badge tone={tone} className="sr-only">
				{tone}
			</Badge>
		</div>
	);
}

/**
 * `ceiling_reached` is a bare boolean and `overflow_mode` says only WHICH
 * mechanism is armed — neither names a day count. `agedOutDays`, when
 * provided, is the CALLER'S computation of `plan.indexed_window_days -
 * auto_age_window_days` (both real gateway numbers) — never invented here.
 * When it is undefined (auto-age's `auto_age_window_days` was null, i.e.
 * nothing has actually shrunk yet) the copy stays generic to what
 * `overflow_mode` guarantees, exactly as before this field existed.
 */
export function CeilingResolvedBanner({
	overflowMode,
	agedOutDays,
	onReview,
}: {
	overflowMode: "auto_age" | "auto_overage";
	/** `plan.indexed_window_days - auto_age_window_days`, only when both are known numbers. */
	agedOutDays?: number;
	onReview: () => void;
}) {
	const explanation =
		overflowMode === "auto_age"
			? agedOutDays !== undefined
				? `the oldest ${agedOutDays} day${agedOutDays === 1 ? "" : "s"} left your indexed window early and remain queryable in cold.`
				: "the oldest data left your indexed window early and remains queryable in cold."
			: "usage past the ceiling is now billed as overage rather than blocked.";
	return (
		<div className="flex flex-wrap items-center justify-between gap-3 rounded-[var(--radius-card)] border border-line bg-surface-2 px-4 py-3">
			<p className="text-sm font-medium text-ink-2">
				Ceiling reached this month — {explanation}{" "}
				{/* Review note: NEUTRAL, never `ok` (green) — a ceiling event is not a win. */}
				{overflowMode === "auto_age" && (
					<Badge tone="neutral">Nothing was lost</Badge>
				)}
			</p>
			<button
				type="button"
				onClick={onReview}
				className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
			>
				Review ceiling
			</button>
		</div>
	);
}
