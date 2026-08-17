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
import { Card, EmptyState, Skeleton } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { VerdictTable } from "./VerdictTable";

export const metadata: Metadata = { title: "Guardrail verdicts — Tracelane" };
export const dynamic = "force-dynamic";

type SP = Record<string, string | undefined>;

const DECISIONS = [
	{ v: "", l: "All" },
	{ v: "block", l: "Blocked" },
	{ v: "redact", l: "Redacted" },
	{ v: "warn", l: "Warned" },
	{ v: "allow", l: "Allowed" },
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
						className="text-[13px] font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
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
							className="text-[13px] font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							Clear filter
						</Link>
					) : undefined
				}
			/>
		);
	}

	return (
		<Card className="overflow-hidden p-0">
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
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mb-4 flex items-center gap-3">
				<Link
					href="/guardrails"
					className="shrink-0 text-sm text-ink-2 transition-colors hover:text-ink"
				>
					← Guardrails
				</Link>
				<h1 className="t-h1">Guardrail verdicts</h1>
			</div>
			<p className="mb-5 max-w-2xl text-sm text-ink-2">
				Why each request was allowed, blocked, redacted or warned. Click a row
				for the full per-rail evidence. Times are UTC.
			</p>

			{/* Correlation-ID lookup — the id returned in a 403 block body pastes
			    straight in, so the reference actually resolves to its verdict. */}
			<form method="get" className="mb-3 flex flex-wrap items-center gap-2">
				{sp.decision && (
					<input type="hidden" name="decision" value={sp.decision} />
				)}
				<input
					type="text"
					name="correlation_id"
					defaultValue={sp.correlation_id ?? ""}
					placeholder="Paste a correlation ID from a 403 response…"
					aria-label="Correlation ID"
					className="w-full max-w-md rounded-sm border border-line bg-surface px-3 py-1.5 font-mono text-[12.5px] text-ink placeholder:font-sans placeholder:text-ink-3 outline-none focus:border-action-line"
				/>
				<button
					type="submit"
					className="rounded-lg border border-line bg-surface px-3 py-1.5 text-[12.5px] font-medium text-ink transition-colors hover:bg-surface-2"
				>
					Find verdict
				</button>
				{sp.correlation_id && (
					<Link
						href={decisionHref(
							{ ...sp, correlation_id: undefined },
							sp.decision ?? "",
						)}
						className="text-[12.5px] text-ink-2 underline underline-offset-2 hover:text-ink"
					>
						Clear
					</Link>
				)}
			</form>

			<div className="mb-5 flex flex-wrap items-center justify-between gap-3">
				<div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
					{DECISIONS.map((d) => (
						<Link
							key={d.v || "all"}
							href={decisionHref(sp, d.v)}
							className={
								active === d.v
									? "rounded-md bg-surface-inverse px-2.5 py-1 text-[12.5px] font-medium text-ink-inverse"
									: "rounded-md px-2.5 py-1 text-[12.5px] text-ink-2 hover:text-ink"
							}
						>
							{d.l}
						</Link>
					))}
				</div>
				<RangeControl />
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
