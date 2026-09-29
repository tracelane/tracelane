import { PageHeader } from "@tracelanedev/ui";
import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";
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
import { ReadFailure } from "@/components/empty-states/ReadFailure";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { fmtSignedDeltaUs } from "@/lib/metrics/format";
import { EmptyState, fmtDur } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Compare traces — Tracelane" };

type SP = Record<string, string | undefined>;

// Duration formatting is `fmtDur` (`@tracelanedev/ui`) and signed-delta formatting
// is `fmtSignedDeltaUs` (`lib/metrics/format.ts`) — both moved out of this page
// (CX-15 / B-514). The page-local `formatDelta` derived its sign from `us` with a
// `"+" : ""` ternary and applied it to `Math.abs(us)`, but a negative `pct` kept
// its OWN minus sign via `toFixed`'s default behaviour: a faster B (negative
// delta) rendered `90.0ms (-90%)` — an unsigned duration beside a signed
// percentage that contradicted it. `fmtSignedDeltaUs` derives the sign from `us`
// once and applies it (via `Math.abs`) to both halves, so they can never disagree.

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
			if (!(err instanceof GatewayError)) throw err;
			return (
				<div className="p-6">
					<PageHeader title={<>Compare traces</>} />
					<ReadFailure
						status={err.status}
						resource="recent traces"
						retryHref={`/traces/compare?a=${encodeURIComponent(a)}`}
					/>
					<Link className="underline" href="/traces">
						Browse traces
					</Link>
				</div>
			);
		}

		return (
			<div className="p-6">
				<PageHeader title={<>Compare traces</>} />
				<p className="mb-4 text-ink-3 text-sm">
					Comparing against <span className="font-mono text-ink">{a}</span> —
					choose the second trace.
				</p>
				{recent.length === 0 ? (
					<EmptyState
						title="No other traces in this recent list"
						description="This picker checks the latest 25 traces. Browse traces to find an older trace, or wait for another trace to arrive."
					/>
				) : (
					<ul className="divide-y divide-line overflow-hidden rounded-card border border-line">
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
			</div>
		);
	}

	// EMPTY — no ids at all. The spec's empty state is about a missing PARAM,
	// not a resolved-but-absent trace (that is a 404 below).
	if (!a || !b) {
		return (
			<div className="p-6">
				<PageHeader title={<>Compare traces</>} />
				<EmptyState
					title="Pick two traces to compare"
					description="Open a trace and choose Compare, or pass ?a=<trace_id>&b=<trace_id>."
				/>
				<p className="mt-4 text-sm">
					<Link className="underline" href="/traces">
						Browse traces
					</Link>
				</p>
			</div>
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
			<div className="p-6">
				<PageHeader title={<>Compare traces</>} />
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
			</div>
		);
	}

	const { rows, threshold_us, threshold_pct } = data;

	return (
		<div className="p-6">
			<PageHeader title={<>Compare traces</>} />
			<p className="text-sm text-ink-3 mb-4">
				{data.only_in_a + data.only_in_b} span
				{data.only_in_a + data.only_in_b === 1 ? "" : "s"} present on one side
				only · {data.slower_count} slower beyond {fmtDur(threshold_us)} and{" "}
				{threshold_pct}%
			</p>

			{/* P0.17: two 32-char trace ids side by side on a 360px phone gave each
			    column ~160px, so every id broke across five mono lines. One column
			    below `sm`. */}
			<div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
				{([data.a, data.b] as const).map((t, i) => (
					<div
						key={t.trace_id}
						className="rounded-card border border-line bg-surface-2 p-3"
					>
						<div className="t-metric-label">Trace {i === 0 ? "A" : "B"}</div>
						<Link
							className="font-mono text-sm underline break-all"
							href={`/traces/${t.trace_id}`}
						>
							{t.trace_id}
						</Link>
						<div className="text-sm mt-1">
							{fmtDur(t.total_us)} · {t.span_count} span
							{t.span_count === 1 ? "" : "s"}
						</div>
					</div>
				))}
			</div>

			<div className="overflow-x-auto">
				<Table className="w-full text-sm">
					<THead>
						<TR className="text-left border-b border-line">
							<TH className="px-3 py-1.5">Span</TH>
							<TH className="px-3 py-1.5 text-right">A</TH>
							<TH className="px-3 py-1.5 text-right">B</TH>
							<TH className="px-3 py-1.5 text-right">Δ</TH>
						</TR>
					</THead>
					<TBody>
						{rows.map((r) => (
							<TR
								key={`${r.name}-${r.depth}-${r.ordinal}-${r.side}`}
								className="border-b border-line"
							>
								<TD className="px-3 py-2">
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
								</TD>
								<TD className="px-3 py-2 text-right font-mono">
									{r.a_duration_us === null ? "—" : fmtDur(r.a_duration_us)}
								</TD>
								<TD className="px-3 py-2 text-right font-mono">
									{r.b_duration_us === null ? "—" : fmtDur(r.b_duration_us)}
								</TD>
								<TD className="px-3 py-2 text-right font-mono">
									{fmtSignedDeltaUs(r.delta_us, r.delta_pct)}
								</TD>
							</TR>
						))}
					</TBody>
				</Table>
			</div>
		</div>
	);
}
