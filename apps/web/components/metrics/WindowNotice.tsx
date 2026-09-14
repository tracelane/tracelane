/**
 * WindowNotice — the honest line under a page title when the window on screen is
 * not exactly the one in the URL (DSH-11 §4): clamped to the family cap, or the
 * URL carried something unparseable and the default preset is in effect.
 * Renders nothing in the normal case. A strip, not a card (the WarmingBanner
 * radius rule), and neutral — a clamp is information, not a warning.
 */

import type { TimeRange } from "@/lib/metrics/time-range";
import { formatWindowUtc } from "@/lib/metrics/time-range";

const DAY = 86_400_000;

export function WindowNotice({ range }: { range: TimeRange }) {
	if (range.invalid) {
		return (
			<p className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-xs text-ink-2">
				The time window in the address could not be read, so this page shows{" "}
				<span className="font-medium text-ink">{range.label}</span>.
			</p>
		);
	}
	if (range.clamped) {
		const capDays = Math.round(range.widthMs / DAY);
		return (
			<p className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-xs text-ink-2">
				Showing the most recent{" "}
				<span className="font-medium text-ink">{capDays} days</span> of the
				range you asked for (limit {capDays} d):{" "}
				<span
					className="font-mono text-ink"
					style={{ fontVariantNumeric: "tabular-nums" }}
				>
					{formatWindowUtc(range.sinceMs, range.untilMs)}
				</span>
				.
			</p>
		);
	}
	return null;
}
