/**
 * Guardrail verdict-detail list — the click-through behind the decision-mix
 * counts on /guardrails ("N blocked" → here, filtered to `decision=block`).
 *
 * Why a verdict list and not a filtered trace list: an inline BLOCK 403s the
 * request BEFORE any span is emitted (server.rs), so a blocked verdict has no
 * trace to link to. The honest detail IS the verdict — which rails fired, their
 * reason codes, score vs threshold, per-rail latency and the rail's `details`
 * payload. Rows expand (see VerdictTable) to show all of it; nothing here is
 * derived. tenant_id comes from the session; the gateway owns the scoped read.
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { fetchGuardrailVerdicts } from "@/lib/guardrails";
import { rangeLabel, rangeToHours } from "@/lib/range";
import {
	Button,
	Card,
	EmptyState,
	SegmentedControl,
	Skeleton,
} from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { VerdictTable } from "./VerdictTable";

export const metadata: Metadata = { title: "Guardrail verdicts — Tracelane" };
export const dynamic = "force-dynamic";

type SP = Record<string, string | undefined>;

const DECISIONS = [
	{ value: "", label: "All" },
	{ value: "block", label: "Blocked" },
	{ value: "redact", label: "Redacted" },
	{ value: "warn", label: "Warned" },
	{ value: "allow", label: "Allowed" },
] as const;

/** Decision filter — server-driven links (preserve the active range). */
function decisionHref(sp: SP, v: string): string {
	const q = new URLSearchParams();
	if (v) q.set("decision", v);
	if (sp.range) q.set("range", sp.range);
	if (sp.correlation_id) q.set("correlation_id", sp.correlation_id);
	const s = q.toString();
	return s ? `/guardrails/verdicts?${s}` : "/guardrails/verdicts";
}

/** Gateway caps the verdict look-back at 720h (MAX_GUARDRAIL_HOURS). */
const LOOKUP_HOURS = 720;

async function VerdictsData({ sp }: { sp: SP }) {
	const lookup = sp.correlation_id?.trim() || undefined;
	// An id lookup ignores the range chip and the decision filter: you paste the
	// id from a 403 and you want THAT verdict, wherever it falls in the window.
	const verdicts = await fetchGuardrailVerdicts(
		lookup
			? { hours: LOOKUP_HOURS, correlationId: lookup, limit: 100 }
			: {
					hours: rangeToHours(sp.range),
					decision: sp.decision,
					limit: 100,
				},
	);

	// Defence in depth: if the gateway is older than this filter it will IGNORE
	// `correlation_id` and return the recent list, which we'd otherwise render as
	// "matches". Re-assert the match here so the page can never show a wrong row
	// (on an old gateway the lookup is simply limited to the fetched window).
	const rows =
		lookup && verdicts
			? verdicts.filter(
					(v) => v.correlation_id.toUpperCase() === lookup.toUpperCase(),
				)
			: verdicts;

	if (verdicts === null) {
		return (
			<>
				<WarmingBanner />
				<EmptyState
					title="Waiting on the gateway"
					description="Verdicts appear here once the gateway is reachable and requests have flowed."
				/>
			</>
		);
	}

	if (rows !== null && rows.length === 0 && lookup) {
		return (
			<EmptyState
				title="No verdict with that correlation ID"
				description={`Nothing matched ${lookup} in the last 30 days (the verdict look-back window). Check the id from the 403 response body, or clear the search.`}
				action={
					<Link
						href={decisionHref({ ...sp, correlation_id: undefined }, "")}
						className="text-sm font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
					>
						Clear search
					</Link>
				}
			/>
		);
	}

	if (rows === null || rows.length === 0) {
		const filtered = Boolean(sp.decision);
		return (
			<EmptyState
				title={
					filtered
						? `No ${sp.decision} verdicts in the last ${rangeLabel(sp.range)}`
						: `No verdicts in the last ${rangeLabel(sp.range)}`
				}
				description="Every request through the gateway is evaluated pre-flight; verdicts land here as traffic flows. Try widening the range or clearing the decision filter."
				action={
					filtered ? (
						<Link
							href={decisionHref({ ...sp, decision: undefined }, "")}
							className="text-sm font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							Clear filter
						</Link>
					) : undefined
				}
			/>
		);
	}

	return (
		// `quiet` — flat. A full-width table is a surface the reader scans, not an
		// object floating in front of the page; the card shadow under a 100%-wide
		// panel reads as a seam. Same call the rail roster makes one click away.
		<Card quiet className="overflow-hidden p-0">
			<VerdictTable verdicts={rows} />
		</Card>
	);
}

export default async function GuardrailVerdictsPage({
	searchParams,
}: {
	searchParams: Promise<SP>;
}) {
	const sp = await searchParams;
	const active = sp.decision ?? "";
	return (
		/* The dashboard's padding ramp, to the utility (verifier, 2026-08-22). This
		   was `px-2 py-3 sm:px-4 sm:py-4`, a different gutter from the four pages
		   that claim the same grammar — measured at 1440 the h1 started at x=269
		   here against x=266 on /dashboard, /gateway, /slo and /signatures. */
		<div className="px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			{/* Page header in the dashboard's grammar: the back link, then `.t-h1`,
			    then ONE line of explanation — and the range control alone on the
			    right, baseline-aligned. It used to sit in the filter row beside the
			    decision segments, which made a row of CONTROLS read as one control
			    with seven options. Copy is unchanged.
			    `mb-8` (29.1px) is the SAME gap the other five pages leave under the
			    header — they get it from a `space-y-8` frame, and this page states it
			    explicitly because its frame is not uniformly spaced: the filter row
			    below belongs to the table it filters and keeps the tighter `mb-5`.
			    It was `mb-5` here and `mb-6` on /guardrails, i.e. three different
			    values for one structural gap. */}
			<header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div>
					<Link
						href="/guardrails"
						className="text-sm text-ink-2 transition-colors hover:text-ink"
					>
						← Guardrails
					</Link>
					<h1 className="mt-1 t-h1">Guardrail verdicts</h1>
					<p className="mt-2 max-w-2xl text-sm text-ink-2">
						Why each request was allowed, blocked, redacted or warned. Click a
						row for the full per-rail evidence. Times are UTC.
					</p>
				</div>
				<RangeControl />
			</header>

			{/* ONE filter row: the decision segments on the left, the correlation-ID
			    lookup on the right. They were two stacked rows plus the range control,
			    i.e. three bands of chrome above the data. The lookup is a real
			    `<form method="get">` and stays one — it must work with JS off, which
			    is the whole point of pasting an id out of a 403 body. */}
			<div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
				{/* Link mode, not button mode: this is a Server Component and the
				    decision filter is a `?decision=` URL param, so each option has to be
				    a real href that works with JS off and is shareable. */}
				<SegmentedControl
					linkAs={Link}
					label="Verdict decision"
					value={active}
					options={DECISIONS}
					hrefFor={(v) => decisionHref(sp, v)}
				/>
				<form method="get" className="flex flex-wrap items-center gap-2">
					{sp.decision && (
						<input type="hidden" name="decision" value={sp.decision} />
					)}
					{/* `rounded-md` (6px), not `rounded-sm` (2px): 2px is not a radius the
					    system defines, and an input beside a `Button` at 6px was visibly
					    squarer than the control it submits to. The height matches the
					    `sm` button (h-8) so the pair reads as one control group. */}
					<input
						type="text"
						name="correlation_id"
						defaultValue={sp.correlation_id ?? ""}
						placeholder="Paste a correlation ID from a 403 response…"
						aria-label="Correlation ID"
						className="h-8 w-full max-w-md rounded-md border border-line bg-surface px-3 font-mono text-xs text-ink placeholder:font-sans placeholder:text-ink-3 focus:border-action-line"
					/>
					<Button type="submit" variant="secondary" size="sm">
						Find verdict
					</Button>
					{sp.correlation_id && (
						<Link
							href={decisionHref(
								{ ...sp, correlation_id: undefined },
								sp.decision ?? "",
							)}
							className="text-xs text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							Clear
						</Link>
					)}
				</form>
			</div>

			<Suspense
				// `range` omitted from the key — the RangeControl transition swaps
				// range data in place (no flash), matching the other range pages; the
				// decision/correlation filters still key the boundary.
				key={`${sp.decision ?? ""}|${sp.correlation_id ?? ""}`}
				fallback={
					<div className="space-y-2">
						{[0, 1, 2, 3, 4].map((i) => (
							<Skeleton key={i} className="h-12 w-full" />
						))}
					</div>
				}
			>
				<VerdictsData sp={sp} />
			</Suspense>
		</div>
	);
}
