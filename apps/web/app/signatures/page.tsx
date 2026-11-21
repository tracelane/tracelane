import { PageHeader } from "@tracelanedev/ui";
import { StatusBadge } from "@tracelanedev/ui";
import { summarizeSignatures } from "./summary";
/**
 * Failure Signatures page (§4) — the AFT-1 taxonomy running live.
 *
 * Reads GET /v1/query/signatures via the gateway proxy — the gateway owns the
 * tenant-scoped live ARRAY JOIN over `spans.aft_ids` and resolves the tenant
 * from the forwarded token. RSC, fetched at request time, window-scoped to the
 * last 30 days.
 *
 * Each row is a REAL detection (not a definition): its per-tenant occurrence
 * count, distinct traces affected, first/last seen, and a link to those traces.
 * `spans.aft_ids` carries the CANONICAL AFT-1 id (one vocabulary — real
 * detectors and the demo seeder both emit canonical ids), which resolves in
 * lib/aft-taxonomy.ts. Entries whose reference detector ships in V1.1 are
 * split into their own roadmap section below the live table — visibly distinct
 * so nothing implies we detect what we don't.
 *
 * Honesty locks:
 *   - NO cross-tenant / network column, and no promise of one. The federation
 *     substrate writes one-way-hashed rows only and has NO cross-tenant read
 *     surface (crates/ingest/src/federation.rs:16) — never render one here.
 *   - NO "failures prevented" stat — detection is live; enforcement is opt-in and
 *     not yet real (AFT-1 observe-first, ADR-055). We never claim prevention.
 *   - Stats are "Signatures matched" + "Traces affected" (the gateway's DISTINCT
 *     trace count, never a sum of per-signature counts) over the window;
 *     per-signature occurrences + traces are the row-level columns.
 *   - "matched" counts ONLY live-detector signatures; roadmap entries are shown
 *     in a separate section and excluded from the headline count.
 *   - Answer first (founder 2026-11-19): ONE answer card states the distinct live
 *     patterns matched, their total occurrences and the DISTINCT traces affected
 *     (`summary.ts`). The two stat tiles it replaced carried the same numbers. A
 *     third figure would have to be a prevention claim, a network count, or a
 *     number nobody computes, and all three are banned above.
 *
 * ── PRESENTATION (P1, 2026-08-22) ───────────────────────────────────────────
 * Both tables are the SHARED `Table` system (`@tracelanedev/ui`), so the header
 * band, row height, hover and alignment rule are the app's rather than this
 * page's: text left, numbers `numeric` (right + tabular + mono, all three), and
 * technical identifiers `mono` in a left column. Each table sits in a `Card
 * quiet` — a table is a flat structured surface, not a floating card, so it
 * takes the hairline and the radius without the lift.
 *
 * THE ROADMAP TABLE'S DASHED BORDER IS GONE. `border-dashed` is the universal
 * idiom for "content failed to load" — the same reason P0.9 deleted it from
 * `EmptyState` — and it was doing work the section heading and its sentence
 * already do in words. Roadmap rows are de-emphasised with INK (`muted`), which
 * is a tone the reader can rank, not a border that reads as breakage.
 *
 * Page furniture follows /dashboard, the P0 reference surface: the same
 * responsive padding ramp, `space-y-8` between sections, and a header whose
 * title is `.t-h1` over one `text-sm text-ink-2` line.
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { WindowNotice } from "@/components/metrics/WindowNotice";
import { LIVE_SIGNATURE_IDS, aftFor } from "@/lib/aft-taxonomy";
import { fetchSignaturesFor } from "@/lib/metrics/fetch";
import { fmtCount } from "@/lib/metrics/format";
import {
	type TimeRange,
	parseTimeRange,
	withWindow,
} from "@/lib/metrics/time-range";
import {
	Badge,
	Card,
	EmptyState,
	Skeleton,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { type SignatureHit, SignatureRow } from "./SignatureRow";

export const metadata: Metadata = { title: "Failure Signatures — Tracelane" };

/**
 * Header row for the live-signatures table — EIGHT columns. The detail panel's
 * `colSpan` reads `SIGNATURE_TABLE_COLS` in SignatureRow.tsx; change one and
 * change the other, or the open row's panel breaks the column grid.
 */
function HeadRow() {
	return (
		<TR>
			{/* The chevron gutter. `px-2` matches the body cell; `aria-label` keeps the
			    column named for a screen reader without printing a visible header. */}
			<TH className="w-10 px-2" aria-label="Expand" />
			<TH>Signature</TH>
			<TH>Pattern ID</TH>
			<TH>Severity</TH>
			<TH numeric>Occurrences</TH>
			<TH numeric>Traces</TH>
			<TH>First seen (UTC)</TH>
			<TH>Last seen (UTC)</TH>
		</TR>
	);
}

/** Header row for the roadmap table (5 cols — no first/last seen, no expand). */
function RoadmapHeadRow() {
	return (
		<TR>
			<TH>Signature</TH>
			<TH>Pattern ID</TH>
			<TH>Planned detection</TH>
			<TH numeric>Occurrences</TH>
			<TH numeric>Traces</TH>
		</TR>
	);
}

/**
 * A single roadmap-section row — no expand/collapse since the planned
 * detection method is shown inline in the third column. Counts shown where
 * present (may reflect demo-seeder data; no live detector emits these yet).
 *
 * Every cell is `muted` (secondary ink) EXCEPT the traces link: the whole row is
 * supporting material, and the one thing in it that DOES something keeps its
 * action tone.
 */
function RoadmapRow({
	sig,
	windowQuery,
}: { sig: SignatureHit; windowQuery: string }) {
	const t = aftFor(sig.signature_id);
	// The destination carries the SAME window as the aggregate (preset or custom).
	const tracesHref = `/traces?signature_id=${encodeURIComponent(sig.signature_id)}&${windowQuery}`;
	return (
		<TR>
			<TD muted className="font-medium">
				{t?.name ?? sig.signature_id}
			</TD>
			{/* Same treatment as the live table: bare mono id for a taxonomy-resolved
			    entry, an `unmapped` chip for one that does not resolve. A roadmap hit
			    resolves by construction (it is FILTERED on detectorStatus), so the
			    chip branch is defensive — but it must agree with the live table or the
			    same column would mean two different things two sections apart. */}
			<TD mono muted className="whitespace-nowrap text-xs">
				{t ? (
					<span title={`${t.name} — AFT-1 taxonomy (CC0)`}>
						{sig.signature_id}
					</span>
				) : (
					<span
						className="inline-flex items-center gap-2"
						title="Unknown id — not in taxonomy map."
					>
						{sig.signature_id}
						<StatusBadge status="unmapped" className="font-sans" />
					</span>
				)}
			</TD>
			<TD muted className="max-w-md">
				{t?.detection ?? "—"}
			</TD>
			<TD numeric muted>
				{fmtCount(sig.your_hits)}
			</TD>
			<TD numeric>
				<Link
					href={tracesHref}
					className="font-medium text-action-ink hover:underline"
				>
					{fmtCount(sig.traces_affected)}
					<span aria-hidden> →</span>
				</Link>
			</TD>
		</TR>
	);
}

/** Static string keys avoid biome's noArrayIndexKey lint. */
const SKELETON_ROW_KEYS = ["sk-a", "sk-b", "sk-c", "sk-d", "sk-e"] as const;

/**
 * The loading shape mirrors the real table CELL FOR CELL — same eight columns,
 * same card, same header band — so the page does not re-flow when data lands.
 * A skeleton whose geometry disagrees with the thing it stands in for is a
 * layout shift with extra steps.
 */
function SignaturesSkeleton() {
	return (
		<div className="space-y-6">
			<Card className="p-5">
				<Skeleton className="mb-3 h-5 w-72" />
				<Skeleton className="h-3 w-96 max-w-full" />
			</Card>
			<Card quiet className="overflow-hidden">
				<Table>
					<THead>
						<HeadRow />
					</THead>
					<TBody>
						{SKELETON_ROW_KEYS.map((k) => (
							<TR key={k}>
								<TD className="w-10 px-2">
									<Skeleton className="h-4 w-4" />
								</TD>
								<TD>
									<Skeleton className="h-4 w-48" />
								</TD>
								<TD>
									<Skeleton className="h-4 w-40" />
								</TD>
								<TD>
									<Skeleton className="h-5 w-14" />
								</TD>
								<TD numeric>
									<Skeleton className="ml-auto h-4 w-10" />
								</TD>
								<TD numeric>
									<Skeleton className="ml-auto h-4 w-10" />
								</TD>
								<TD>
									<Skeleton className="h-4 w-24" />
								</TD>
								<TD>
									<Skeleton className="h-4 w-24" />
								</TD>
							</TR>
						))}
					</TBody>
				</Table>
			</Card>
		</div>
	);
}

async function SignaturesData({ range }: { range: TimeRange }) {
	// Scope "traces affected" to LIVE detector ids so it matches its hint and
	// never counts a demo-seeder roadmap id (provenance audit P2 #11). The
	// gateway format-validates + binds each id.
	const data = await fetchSignaturesFor(range, LIVE_SIGNATURE_IDS);
	if (data === null) {
		// Unreachable ≠ "nothing matched" (B-334): the old title here was the
		// zero-shaped one, so an outage read as a clean bill of health.
		return (
			<>
				<WarmingBanner />
				<EmptyState
					title="Waiting on the gateway"
					description="Signatures appear here once the gateway is reachable and a request matches a known failure pattern."
				/>
			</>
		);
	}
	const signatures: SignatureHit[] = data.signatures;
	// Distinct traces with at least one LIVE signature — a trace hitting several
	// counts once. NEVER the sum of per-signature counts (that double-counts).
	// `null` is UNKNOWN (an older gateway) and renders `—`, never `?? 0`.
	const tracesAffected = data.total_traces_affected;
	const windowQuery = withWindow("", range).replace(/^\?/, "");

	// Split live-detected signatures from roadmap entries so the two surfaces
	// are never conflated. Live → main table. Roadmap → separate section below.
	const live = signatures.filter(
		(s) => aftFor(s.signature_id)?.detectorStatus !== "roadmap",
	);
	const roadmapHits = signatures.filter(
		(s) => aftFor(s.signature_id)?.detectorStatus === "roadmap",
	);
	// "matched" is the live-detector count only — roadmap entries excluded.
	const matched = live.length;

	return (
		<div className="space-y-6">
			{/* Answer first (founder 2026-11-19): one sentence answers "did my agents hit a
			    known failure pattern?" with its scope. Both counts (matches and distinct
			    traces affected) live in that sentence, so the two large volume tiles are
			    gone: one card instead of two big numbers, and no zeros on a quiet day. */}
			{(() => {
				const a = summarizeSignatures(
					matched,
					live.reduce((t, x) => t + x.your_hits, 0),
					tracesAffected,
					range.label,
				);
				return (
					<section
						data-signatures-answer={a.tone}
						className="border border-line bg-surface p-5"
					>
						<h2 className="text-lg font-semibold tracking-tight">
							{a.headline}
						</h2>
						<p className="mt-2 max-w-2xl text-sm text-ink-2">{a.detail}</p>
						{matched === 0 && (
							<Link
								href="/traces"
								className="mt-4 inline-block text-sm font-medium text-action-ink hover:underline"
							>
								Browse recent traces →
							</Link>
						)}
					</section>
				);
			})()}

			{/* LIVE TABLE — only signatures with a shipped reference detector. */}
			{matched > 0 && (
				<Card quiet className="overflow-hidden">
					<Table>
						<THead>
							<HeadRow />
						</THead>
						<TBody>
							{live.map((s) => (
								<SignatureRow
									key={s.signature_id}
									sig={s}
									windowQuery={windowQuery}
								/>
							))}
						</TBody>
					</Table>
				</Card>
			)}

			{/* ROADMAP SECTION — V1.1 taxonomy entries whose detector hasn't shipped.
			    Shown only when the API response includes roadmap ids (demo seeder may
			    emit them). Counts shown as-is but clearly framed as roadmap data.
			    In production with no demo seeder these ids produce zero hits and this
			    section does not render.

			    The heading is `.t-eyebrow` — the ONE section-label role in the type
			    system. It was `text-base font-semibold`, a private near-copy that made
			    a supporting section shout at 16px directly under a 13px page
			    description. The COPY is unchanged. */}
			{roadmapHits.length > 0 && (
				<section className="space-y-4 border-t border-line pt-8">
					<div>
						<h2 className="t-eyebrow">Not detected live yet</h2>
						<p className="mt-1.5 max-w-2xl text-sm text-ink-2">
							These patterns are defined, but their detectors are not live yet,
							so these counts do not come from live detection of your traffic.
						</p>
					</div>
					<Card quiet className="overflow-hidden">
						<Table>
							<THead>
								<RoadmapHeadRow />
							</THead>
							<TBody>
								{roadmapHits.map((s) => (
									<RoadmapRow
										key={s.signature_id}
										sig={s}
										windowQuery={windowQuery}
									/>
								))}
							</TBody>
						</Table>
					</Card>
				</section>
			)}
		</div>
	);
}

// Queries ClickHouse (via the gateway) at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function SignaturesPage({
	searchParams,
}: {
	searchParams: Promise<{ range?: string; since?: string; until?: string }>;
}) {
	const sp = await searchParams;
	const range = parseTimeRange(sp, { defaultPreset: "30d", nowMs: Date.now() });
	return (
		// Padding ramp + `space-y-8` copied from /dashboard, the P0 reference
		// surface: this page pinned `px-2 py-3` and sat ~7px off the content
		// column's edge at every viewport.
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			{/* The same header BOX as /dashboard, /gateway, /slo and the two
			    /guardrails pages, not merely the same type (verifier, 2026-08-22).
			    This was a bare `<header>` at `display:block`; the title and subtitle
			    render identically either way, so nothing moves — what changes is that
			    the title/subtitle stack is now the flex child every other page has, so
			    a control added here lands baseline-right like the RangeControl does
			    elsewhere instead of stacking under the copy. A structure that is only
			    accidentally identical is the one that diverges the next time it is
			    edited. */}
			<header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div>
					<PageHeader title={<>Failure Signatures</>} />
					<p className="mt-2 max-w-2xl text-sm text-ink-2">
						Known agent failure patterns found in your recorded calls, how often
						each happened, and the traces it touched.
					</p>
				</div>
				<RangeControl defaultPreset="30d" />
			</header>
			<WindowNotice range={range} />
			<Suspense fallback={<SignaturesSkeleton />}>
				<SignaturesData range={range} />
			</Suspense>
		</div>
	);
}
