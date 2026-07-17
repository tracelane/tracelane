/**
 * `?range=` preset → the values a server-rendered page threads into its fetches.
 * Shared by Dashboard / SLO / Gateway (see components/RangeControl). Default 24h.
 * The /v1/slo, /v1/gateway/stats, and /v1/query/* endpoints all take `hours`.
 */

const HOURS: Record<string, number> = { "24h": 24, "7d": 168, "30d": 720 };
const LABEL: Record<string, string> = {
	"24h": "24 hours",
	"7d": "7 days",
	"30d": "30 days",
};
const SHORT: Record<string, string> = {
	"24h": "24h",
	"7d": "7d",
	"30d": "30d",
};

/** Look-back hours for the *_stats/slo endpoints. Unknown/absent → 24. */
export function rangeToHours(range: string | undefined): number {
	return (range && HOURS[range]) || 24;
}

/** Human label for copy ("last 24 hours"). */
export function rangeLabel(range: string | undefined): string {
	return (range && LABEL[range]) || "24 hours";
}

/** Short label + the normalised `?range=` token for hrefs (so drill-through matches). */
export function rangeShort(range: string | undefined): string {
	return (range && SHORT[range]) || "24h";
}

/**
 * Time-series bucket width (ms) for a range — chosen so a chart never draws more
 * than ~30 bars: 24h → 1h, 7d → 6h, 30d → 1d. Keeps the hourly SLO rows honest
 * at every range (collapsed into wider buckets) instead of truncating at the
 * chart's 48-bucket cap. Unknown/absent → hourly.
 */
const BUCKET_MS: Record<string, number> = {
	"24h": 3_600_000,
	"7d": 21_600_000,
	"30d": 86_400_000,
};
export function rangeBucketMs(range: string | undefined): number {
	return (range && BUCKET_MS[range]) || 3_600_000;
}
