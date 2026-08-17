"use client";

/**
 * TraceList — client component that renders a table of trace summaries.
 *
 * Whole-row click navigates to the trace detail page. The inner Link in the
 * operation cell preserves keyboard accessibility. Status column uses the
 * shared Badge primitive: ok / danger / warn — never Lava text on links.
 *
 * Columns: root operation, model, TIMELINE, duration, spans, tokens, cost, status,
 * started.
 *
 * ── WHY THERE IS A TIMELINE COLUMN (ADR-074 §7, 2026-08-16) ──────────────────────
 * §7 asks for one precision time axis "used identically on the traces list, waterfall,
 * sessions and every dashboard chart". On this surface that could not simply be a
 * `TimeRuler` strip above the table, and the reason is structural rather than cosmetic:
 * **this table's x-axis is COLUMNS and its time axis is VERTICAL (row order).** Time was
 * text in the last cell. A horizontal ruler over it would be an axis for a dimension
 * nothing is positioned along — it would align to nothing, by construction, and would
 * read as decoration the moment anyone looked closely.
 *
 * So the rows gained a real time dimension first. Each trace draws a bar positioned by
 * its true start and sized by its true duration, and the ruler sits in that column's
 * `<th>`. Alignment then holds BY CONSTRUCTION — the ruler and the bars are the same
 * table column, so whatever width the browser's automatic layout gives it, both get the
 * same box. That mattered: there is no `table-fixed` and no `<colgroup>` anywhere in
 * this repo, so a ruler mounted anywhere else would drift with the content.
 *
 * THE WINDOW COMES FROM THE ROWS, NEVER FROM `?range=`. The URL window can be far wider
 * than the data: the page requests the newest 25 rows inside it, so a busy tenant's "last
 * hour" may render two minutes of traces. An axis drawn from the URL range would be up to
 * 30x wider than everything beneath it. Deriving it here also means it survives
 * `LiveTraces` swapping the whole server subtree for a bare `<TraceList traces={rows}/>`,
 * and it uses no `Date.now()` at all — so there is no server/client hydration split.
 */

import { formatStartedUtc, parseUtcMs } from "@/lib/format-date";
import { Badge, EmptyState, TimeRuler, cn, fmtDur } from "@tracelanedev/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";

export type TraceSummary = {
	trace_id: string;
	root_name: string;
	start_time: string;
	duration_us: number;
	span_count: number;
	error_count: number;
	intervention: number;
	model: string;
	/** Summed real cost (USD) over the trace's spans; 0 when unpriced. */
	cost_usd: number;
	/** Summed input + output tokens over the trace's spans; 0 when no usage. */
	total_tokens: number;
};

/**
 * The window every row's bar is drawn in: earliest start to latest end across the
 * traces actually rendered. Returns null when there is nothing to draw an axis over —
 * a single instantaneous trace, or unparseable timestamps — so the caller can omit the
 * column rather than render an axis of zero width.
 *
 * `parseUtcMs`, never `new Date(row.start_time)`: the gateway sends a NAIVE ClickHouse
 * string (`2026-06-10 12:34:56.123456`, no `T`, no `Z`) which `Date` parses as LOCAL.
 * That exact bug already shipped once — a trace at 08:45 UTC rendered as "03:15 UTC"
 * for an IST viewer (`lib/format-date.ts:32-48`).
 */
function traceWindow(
	traces: TraceSummary[],
): { startMs: number; endMs: number } | null {
	let startMs = Number.POSITIVE_INFINITY;
	let endMs = Number.NEGATIVE_INFINITY;
	for (const t of traces) {
		const s = parseUtcMs(t.start_time);
		if (!Number.isFinite(s)) continue;
		const e = s + Math.max(0, t.duration_us) / 1_000;
		if (s < startMs) startMs = s;
		if (e > endMs) endMs = e;
	}
	if (!Number.isFinite(startMs) || !(endMs > startMs)) return null;
	return { startMs, endMs };
}

/** Cost as USD; `—` for zero/absent so the column reads honestly, not "$0.00". */
function formatCost(usd: number): string {
	if (!usd) return "—";
	return usd < 0.01 ? `$${usd.toFixed(4)}` : `$${usd.toFixed(2)}`;
}

/** Compact token count (1.2K / 1.4M); `—` for zero/absent. */
function formatTokens(n: number): string {
	if (!n) return "—";
	if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
	return `${n}`;
}

/**
 * Intervention / policy badge. Severity is deliberately distinct from runtime
 * errors so a policy-block (warn amber) is never confused with a crash (danger
 * red). Both levels share the warn amber to indicate "guardrail acted"; the
 * text label ("blocked" vs "warned") distinguishes the outcome.
 *
 * blocked (2) = warn — pre-flight policy enforcement stopped the action
 * warned  (1) = warn — advisory raised, action continued
 */
function InterventionBadge({ level }: { level: number }) {
	if (level === 0) return null;
	return <Badge tone="warn">{level === 2 ? "blocked" : "warned"}</Badge>;
}

/**
 * One trace's bar, positioned by its real start and sized by its real duration inside
 * the shared window. Same geometry the waterfall uses on spans, one level up.
 *
 * EMPHASIS IS INK WEIGHT, NEVER HUE (ADR-074 §1) — an errored trace is the one
 * exception, and it carries the `danger` token because "this failed" is meaning, which
 * is what colour is reserved for. The bar is never the only signal: the Status column
 * still says so in words.
 *
 * A 0.6% minimum width is a VISIBILITY floor, not a duration claim — a 4ms trace inside
 * a 40-minute window is genuinely sub-pixel, and a bar you cannot see reads as missing
 * data. The exact number stays in the Duration column beside it, unrounded.
 */
function TraceBar({
	trace,
	win,
}: {
	trace: TraceSummary;
	win: { startMs: number; endMs: number };
}) {
	const span = win.endMs - win.startMs;
	const startMs = parseUtcMs(trace.start_time);
	if (!Number.isFinite(startMs) || span <= 0) {
		// A row whose timestamp would not parse gets no bar rather than a bar at zero —
		// position 0 would assert "this ran first", which is not what we know.
		return <span className="sr-only">timeline unavailable</span>;
	}
	const leftPct = ((startMs - win.startMs) / span) * 100;
	const rawWidth = (trace.duration_us / 1_000 / span) * 100;
	const widthPct = Math.min(
		Math.max(rawWidth, 0.6),
		Math.max(0, 100 - leftPct),
	);
	const isError = trace.error_count > 0;

	return (
		<span className="relative flex h-4 items-center" aria-hidden="true">
			{/* Faint track so a row with a sub-pixel bar still reads as a lane. */}
			<span className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-line/60" />
			<span
				className={cn(
					"absolute top-1/2 h-2 -translate-y-1/2 rounded-sm",
					isError ? "bg-danger" : "bg-ink-2/70",
				)}
				style={{ left: `${leftPct}%`, width: `${widthPct}%` }}
			/>
		</span>
	);
}

/** Sortable column header — uppercase-muted grammar + seal focus ring. */
function SortHeader({
	label,
	href,
	active,
	order,
	align = "text-left",
}: {
	label: string;
	href: string;
	active: boolean;
	order: string;
	align?: string;
}) {
	return (
		<th
			className={`px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-ink-3 ${align}`}
		>
			<a
				href={href}
				className="inline-flex items-center gap-1 transition-colors hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
			>
				{label}
				<span className="text-[10px]">
					{active ? (order === "asc" ? "↑" : "↓") : "↕"}
				</span>
			</a>
		</th>
	);
}

export function TraceList({
	traces,
	sort = "start_time",
	order = "desc",
	durationHref,
	startedHref,
	spansHref,
}: {
	traces: TraceSummary[];
	sort?: string;
	order?: string;
	durationHref?: string;
	startedHref?: string;
	spansHref?: string;
}) {
	const router = useRouter();

	if (traces.length === 0) {
		return (
			<EmptyState
				title="No traces yet"
				description="Point your agents at the gateway to start capturing traces."
			/>
		);
	}

	// Null when the rendered rows span no measurable time (one instantaneous trace, or
	// timestamps that would not parse). The column is then omitted entirely rather than
	// rendered as a flat axis — an axis with no span asserts a scale that does not exist.
	const win = traceWindow(traces);

	return (
		<div className="overflow-x-auto rounded-lg border border-line bg-surface">
			<table className="w-full text-sm">
				<thead>
					<tr>
						<th className="px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Operation
						</th>
						<th
							className="px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3"
							title="The first model seen in the trace. A trace that switches models mid-run shows every model in its detail view; the sessions list shows the latest model."
						>
							Model
						</th>
						{win && (
							// ADR-074 §7's ruler, inside the column whose bars it describes —
							// see the header comment for why it cannot sit above the table.
							// `w-[26%]` is a hint to the browser's automatic layout, not a
							// correctness requirement: ruler and bars share this cell's box
							// whatever width it ends up with.
							<th
								className="w-[26%] min-w-[10rem] px-3 py-1.5 align-bottom"
								title={`Each bar is one trace, positioned by its real start and sized by its real duration, across the ${fmtDur((win.endMs - win.startMs) * 1000)} these ${traces.length} traces span. UTC.`}
							>
								<span className="sr-only">Timeline</span>
								{/*
								 * `absolute` and `ticks={4}` are both CHOSEN, neither is a default.
								 *
								 * ABSOLUTE because a LIST must not change frame with its data. Under the
								 * component's auto behaviour a page spanning 50 seconds renders elapsed
								 * ("0s · 15s · 30s") while the same column at five minutes renders
								 * wall-clock — the axis would mean two different things depending on how
								 * busy the tenant was. Wall-clock also agrees with the Started column
								 * beside it, which is minute-precision; the ruler is what adds the
								 * seconds back.
								 *
								 * FOUR rather than the default six because these labels are `10:00:15`,
								 * not `0s`. Tick density is the one thing the ruler cannot decide for
								 * itself — it renders server-side with no pixel width, so it cannot know
								 * when two labels would touch. At six, the last two collided here.
								 */}
								<TimeRuler
									startMs={win.startMs}
									endMs={win.endMs}
									ticks={4}
									mode="absolute"
								/>
							</th>
						)}
						{durationHref ? (
							<SortHeader
								label="Duration"
								href={durationHref}
								active={sort === "duration"}
								order={order}
								align="text-right"
							/>
						) : (
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Duration
							</th>
						)}
						{spansHref ? (
							<SortHeader
								label="Spans"
								href={spansHref}
								active={sort === "spans"}
								order={order}
								align="text-right"
							/>
						) : (
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Spans
							</th>
						)}
						<th
							className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3"
							title="Tokens/cost sum per span — may double-count when usage is recorded on both a wrapper and its inner span. '—' = unpriced or no usage, not necessarily zero."
						>
							Tokens
						</th>
						<th
							className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3"
							title="Tokens/cost sum per span — may double-count when usage is recorded on both a wrapper and its inner span. '—' = unpriced or no usage, not necessarily zero."
						>
							Cost
						</th>
						<th className="px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Status
						</th>
						{startedHref ? (
							<SortHeader
								label="Started (UTC)"
								href={startedHref}
								active={sort === "start_time"}
								order={order}
							/>
						) : (
							<th className="px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Started (UTC)
							</th>
						)}
					</tr>
				</thead>
				<tbody className="divide-y">
					{traces.map((t) => (
						// biome-ignore lint/a11y/useKeyWithClickEvents: keyboard users navigate via the focusable name Link below (same href); the row onClick is a mouse-only convenience, not the sole path.
						<tr
							key={t.trace_id}
							className="cursor-pointer transition-colors hover:bg-surface-2 active:bg-action-soft focus-within:bg-surface-2"
							onClick={() => router.push(`/traces/${t.trace_id}`)}
						>
							<td className="px-3 py-2">
								<Link
									href={`/traces/${t.trace_id}`}
									onClick={(e) => e.stopPropagation()}
									className="font-medium text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
								>
									{t.root_name || t.trace_id.slice(0, 16)}
								</Link>
								<span className="ml-2 font-mono text-xs text-ink-3">
									{t.trace_id.slice(0, 8)}
								</span>
							</td>
							<td className="px-3 py-2 font-mono text-xs text-ink-2">
								{t.model || "—"}
							</td>
							{win && (
								<td className="px-3 py-2">
									<TraceBar trace={t} win={win} />
								</td>
							)}
							<td className="px-3 py-2 text-right font-mono text-xs tabular-nums">
								{fmtDur(t.duration_us)}
							</td>
							<td className="px-3 py-2 text-right font-mono text-xs tabular-nums">
								{t.span_count}
							</td>
							<td className="px-3 py-2 text-right font-mono text-xs tabular-nums">
								{formatTokens(t.total_tokens)}
							</td>
							<td className="px-3 py-2 text-right font-mono text-xs tabular-nums">
								{formatCost(t.cost_usd)}
							</td>
							<td className="px-3 py-2">
								<div className="flex items-center gap-1.5">
									{t.error_count > 0 && (
										<Badge tone="danger">
											{t.error_count} error{t.error_count > 1 ? "s" : ""}
										</Badge>
									)}
									<InterventionBadge level={t.intervention} />
									{t.error_count === 0 && t.intervention === 0 && (
										<Badge tone="ok">OK</Badge>
									)}
								</div>
							</td>
							<td className="px-3 py-2 tabular-nums text-xs text-ink-3">
								<time dateTime={t.start_time} title={t.start_time}>
									{formatStartedUtc(t.start_time)}
								</time>
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
