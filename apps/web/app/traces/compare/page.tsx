/**
 * OBS-10 — trace compare. Two traces, one screen.
 *
 * Server Component: the gateway owns the tenant-scoped ClickHouse read and the
 * alignment; this page renders what it returns and nothing more. There is no
 * ClickHouse client here and there must never be (apps/web/CLAUDE.md).
 *
 * Every number on screen is defined by the gateway response, including the two
 * thresholds behind the ▲ marker — they are echoed in the payload precisely so
 * this page never hardcodes a rule it would then have to keep in step.
 */

import type { TraceCompareResponse } from "@/app/api/traces/compare/route";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Compare traces — Tracelane" };

type SP = Record<string, string | undefined>;

/** Same scale as the trace list, so a duration reads identically on both pages. */
function formatDuration(us: number): string {
	if (us < 1_000) return `${us}µs`;
	if (us < 1_000_000) return `${(us / 1_000).toFixed(1)}ms`;
	return `${(us / 1_000_000).toFixed(2)}s`;
}

/** Signed delta. `—` when there is nothing to compare (a one-sided row). */
function formatDelta(us: number | null, pct: number | null): string {
	if (us === null) return "—";
	const sign = us > 0 ? "+" : "";
	// pct is null when the A-side duration was 0. Show the absolute move and
	// omit the ratio rather than inventing one.
	return pct === null
		? `${sign}${formatDuration(Math.abs(us))}`
		: `${sign}${formatDuration(Math.abs(us))} (${sign}${pct.toFixed(0)}%)`;
}

/** The few fields the picker renders — deliberately not the full list row type. */
type PickerTrace = { trace_id: string; root_name: string };

export default async function CompareTracesPage({
	searchParams,
}: {
	searchParams: Promise<SP>;
}) {
	const sp = await searchParams;
	const a = sp.a?.trim();
	const b = sp.b?.trim();

	// ONE id present — render a PICKER for the second, which is what un-strands this
	// route. Until 2026-08-15 the empty state said "Open a trace and choose Compare"
	// and NO Compare control existed anywhere in the app: the page rendered a working
	// diff that nothing could reach, and only a hand-typed URL with both params got
	// here. The R12 before-inventory flagged it as the one genuinely stranded surface
	// and the founder named it as the exact failure the migration must not repeat.
	// The flow is now: trace detail → Compare → pick the second → diff.
	if (a && !b) {
		let recent: PickerTrace[] = [];
		try {
			const d = await gatewayGet<{ traces: PickerTrace[] }>(
				"/v1/traces?limit=25",
			);
			recent = d.traces.filter((x) => x.trace_id !== a);
		} catch (err) {
			// A picker we cannot populate is still better than a dead end: fall through
			// to the manual instruction rather than erroring the whole page.
			if (!(err instanceof GatewayError)) throw err;
		}

		return (
			<main className="p-6">
				<h1 className="t-h1 mb-1">Compare traces</h1>
				<p className="mb-4 text-ink-3 text-sm">
					Comparing against <span className="font-mono text-ink">{a}</span> —
					choose the second trace.
				</p>
				{recent.length === 0 ? (
					<EmptyState
						title="No other traces to compare against"
						description="Only one trace is available in this workspace right now."
					/>
				) : (
					<ul className="divide-y divide-line overflow-hidden rounded-lg border border-line">
						{recent.map((tr) => (
							<li key={tr.trace_id}>
								<Link
									href={`/traces/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(tr.trace_id)}`}
									className="flex items-center justify-between gap-4 px-3 py-2 transition-colors hover:bg-surface-hover"
								>
									<span className="min-w-0 flex-1 truncate text-ink text-sm">
										{tr.root_name || "(unnamed)"}
									</span>
									<span
										className="shrink-0 font-mono text-2xs text-ink-3"
										style={{ fontVariantNumeric: "tabular-nums" }}
									>
										{tr.trace_id.slice(0, 12)}…
									</span>
								</Link>
							</li>
						))}
					</ul>
				)}
				<p className="mt-4 text-sm">
					<Link className="underline" href="/traces">
						Browse traces
					</Link>
				</p>
			</main>
		);
	}

	// EMPTY — no ids at all. The spec's empty state is about a missing PARAM,
	// not a resolved-but-absent trace (that is a 404 below).
	if (!a || !b) {
		return (
			<main className="p-6">
				<h1 className="t-h1 mb-4">Compare traces</h1>
				<EmptyState
					title="Pick two traces to compare"
					description="Open a trace and choose Compare, or pass ?a=<trace_id>&b=<trace_id>."
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/traces">
						Browse traces
					</Link>
				</p>
			</main>
		);
	}

	let data: TraceCompareResponse;
	try {
		data = await gatewayGet<TraceCompareResponse>(
			`/v1/traces/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`,
		);
	} catch (err) {
		// ERROR — and the status matters. A 404 (unknown id, or an id belonging to
		// another tenant — deliberately indistinguishable) is a different answer
		// from "the gateway is down", and collapsing them into one message is the
		// defect that made an owner-only 403 read as a generic failure.
		const status = err instanceof GatewayError ? err.status : 0;
		const notFound = status === 404;
		return (
			<main className="p-6">
				<h1 className="t-h1 mb-4">Compare traces</h1>
				<EmptyState
					title={notFound ? "Trace not found" : "Couldn't load the comparison"}
					description={
						notFound
							? "One or both of these traces don't exist in this workspace."
							: "The gateway couldn't be reached. Nothing is wrong with these traces — try again."
					}
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/traces">
						Back to traces
					</Link>
				</p>
			</main>
		);
	}

	const { rows, threshold_us, threshold_pct } = data;

	return (
		<main className="p-6">
			<h1 className="t-h1 mb-1">Compare traces</h1>
			<p className="text-sm text-ink-3 mb-4">
				{data.only_in_a + data.only_in_b} span
				{data.only_in_a + data.only_in_b === 1 ? "" : "s"} present on one side
				only · {data.slower_count} slower beyond {formatDuration(threshold_us)}{" "}
				and {threshold_pct}%
			</p>

			{/* P0.17: two 32-char trace ids side by side on a 360px phone gave each
			    column ~160px, so every id broke across five mono lines. One column
			    below `sm`. */}
			<div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
				{([data.a, data.b] as const).map((t, i) => (
					<div
						key={t.trace_id}
						className="rounded-lg border border-line bg-surface-2 p-3"
					>
						<div className="t-metric-label">Trace {i === 0 ? "A" : "B"}</div>
						<Link
							className="font-mono text-sm underline break-all"
							href={`/traces/${t.trace_id}`}
						>
							{t.trace_id}
						</Link>
						<div className="text-sm mt-1">
							{formatDuration(t.total_us)} · {t.span_count} span
							{t.span_count === 1 ? "" : "s"}
						</div>
					</div>
				))}
			</div>

			<div className="overflow-x-auto">
				<table className="w-full text-sm">
					<thead>
						<tr className="text-left border-b border-line">
							<th className="px-3 py-1.5">Span</th>
							<th className="px-3 py-1.5 text-right">A</th>
							<th className="px-3 py-1.5 text-right">B</th>
							<th className="px-3 py-1.5 text-right">Δ</th>
						</tr>
					</thead>
					<tbody>
						{rows.map((r) => (
							<tr
								key={`${r.name}-${r.depth}-${r.ordinal}-${r.side}`}
								className="border-b border-line"
							>
								<td className="px-3 py-2">
									<span style={{ paddingLeft: `${r.depth * 14}px` }}>
										{r.name}
									</span>
									{/* Marker AND text: a symbol alone conveys state by glyph
									    only, and these two states must survive a screen reader
									    (the selected-by-colour-alone finding, generalised). */}
									{r.side === "only_a" && (
										<span className="ml-2 text-xs">+ only in A</span>
									)}
									{r.side === "only_b" && (
										<span className="ml-2 text-xs">+ only in B</span>
									)}
									{r.slower && <span className="ml-2 text-xs">▲ slower</span>}
								</td>
								<td className="px-3 py-2 text-right font-mono">
									{r.a_duration_us === null
										? "—"
										: formatDuration(r.a_duration_us)}
								</td>
								<td className="px-3 py-2 text-right font-mono">
									{r.b_duration_us === null
										? "—"
										: formatDuration(r.b_duration_us)}
								</td>
								<td className="px-3 py-2 text-right font-mono">
									{formatDelta(r.delta_us, r.delta_pct)}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</main>
	);
}
