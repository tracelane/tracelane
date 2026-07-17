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
 *   - NO cross-tenant / network column — that signal is V1.1.
 *   - NO "failures prevented" stat — detection is live; enforcement is opt-in and
 *     not yet real (AFT-1 observe-first, ADR-055). We never claim prevention.
 *   - Stats are "Signatures matched" + "Traces affected" (the gateway's DISTINCT
 *     trace count, never a sum of per-signature counts) over the window;
 *     per-signature occurrences + traces are the row-level columns.
 *   - "matched" counts ONLY live-detector signatures; roadmap entries are shown
 *     in a separate section and excluded from the headline count.
 *
 * DS v2 notes: metric tiles use the shared <StatCard>; names render in ink
 * (red is reserved for a real Block severity); the AFT-1 id is the violet data
 * hue; table headers are uppercase-muted.
 */

import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { aftFor } from "@/lib/aft-taxonomy";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { Badge, Card, EmptyState, Skeleton, StatCard } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { type SignatureHit, SignatureRow } from "./SignatureRow";

export const metadata: Metadata = { title: "Failure Signatures — Tracelane" };

/** Window for the live aggregate — last 30 days. */
const WINDOW_DAYS = 30;

/** Header row for the live-signatures table (8 cols). */
function HeadRow() {
	const th =
		"px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3";
	const thR = `${th} text-right`;
	return (
		<tr>
			<th className="w-8 py-2 pl-4" aria-label="Expand" />
			<th className={th}>Signature</th>
			<th className={th}>AFT-1</th>
			<th className={th}>Severity</th>
			<th className={thR}>Occurrences</th>
			<th className={thR}>Traces</th>
			<th className={th}>First seen</th>
			<th className={th}>Last seen</th>
		</tr>
	);
}

/** Header row for the roadmap table (5 cols — no first/last seen, no expand). */
function RoadmapHeadRow() {
	const th =
		"px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3";
	const thR = `${th} text-right`;
	return (
		<tr>
			<th className={th}>Signature</th>
			<th className={th}>AFT-1</th>
			<th className={th}>Planned detection · V1.1</th>
			<th className={thR}>Occurrences</th>
			<th className={thR}>Traces</th>
		</tr>
	);
}

/**
 * A single roadmap-section row — no expand/collapse since the planned
 * detection method is shown inline in the third column. Counts shown where
 * present (may reflect demo-seeder data; no live detector emits these yet).
 */
function RoadmapRow({ sig }: { sig: SignatureHit }) {
	const t = aftFor(sig.signature_id);
	// range=30d so the destination matches the 30-day signature aggregate.
	const tracesHref = `/traces?signature_id=${encodeURIComponent(sig.signature_id)}&range=30d`;
	return (
		<tr className="align-top">
			<td className="px-4 py-3">
				<div className="font-medium text-ink-2">
					{t?.name ?? sig.signature_id}
				</div>
				<div className="font-mono text-xs text-ink-3">{sig.signature_id}</div>
			</td>
			<td className="px-4 py-3">
				<Badge
					tone="neutral"
					className="font-mono"
					title={
						t
							? `${t.name} — AFT-1 taxonomy (CC0)`
							: "Unknown id — not in taxonomy map."
					}
				>
					{sig.signature_id}
				</Badge>
			</td>
			<td className="max-w-xs px-4 py-3 text-sm text-ink-3">
				{t?.detection ?? "—"}
			</td>
			<td className="px-4 py-3 text-right tabular-nums text-sm text-ink-3">
				{sig.your_hits.toLocaleString()}
			</td>
			<td className="px-4 py-3 text-right">
				<Link
					href={tracesHref}
					className="font-medium tabular-nums text-sm text-accent-ink hover:underline"
				>
					{sig.traces_affected.toLocaleString()}
					<span aria-hidden> →</span>
				</Link>
			</td>
		</tr>
	);
}

/** Static string keys avoid biome's noArrayIndexKey lint. */
const SKELETON_ROW_KEYS = ["sk-a", "sk-b", "sk-c", "sk-d", "sk-e"] as const;

function SignaturesSkeleton() {
	return (
		<div className="space-y-6">
			<div className="grid grid-cols-2 gap-4 sm:max-w-md">
				{(["mc-a", "mc-b"] as const).map((k) => (
					<Card key={k} className="p-4">
						<Skeleton className="mb-2 h-3 w-24" />
						<Skeleton className="h-7 w-16" />
					</Card>
				))}
			</div>
			<div className="overflow-x-auto rounded-lg border border-line">
				<table className="w-full text-sm">
					<thead className="bg-surface-2/50">
						<HeadRow />
					</thead>
					<tbody className="divide-y divide-line">
						{SKELETON_ROW_KEYS.map((k) => (
							<tr key={k}>
								<td className="py-2 pl-4">
									<Skeleton className="h-4 w-4" />
								</td>
								<td className="py-2 pr-4">
									<Skeleton className="mb-1 h-4 w-40" />
									<Skeleton className="h-3 w-28" />
								</td>
								<td className="px-4 py-2">
									<Skeleton className="h-5 w-28" />
								</td>
								<td className="px-4 py-2">
									<Skeleton className="h-5 w-14" />
								</td>
								<td className="px-4 py-2 text-right">
									<Skeleton className="ml-auto h-4 w-8" />
								</td>
								<td className="px-4 py-2 text-right">
									<Skeleton className="ml-auto h-4 w-8" />
								</td>
								<td className="px-4 py-2">
									<Skeleton className="h-3 w-20" />
								</td>
								<td className="px-4 py-2">
									<Skeleton className="h-3 w-16" />
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}

async function SignaturesData() {
	let signatures: SignatureHit[];
	let tracesAffected = 0;
	try {
		const since = new Date(Date.now() - WINDOW_DAYS * 86_400_000).toISOString();
		const data = await gatewayGet<{
			signatures: SignatureHit[];
			total_traces_affected: number;
		}>(`/v1/query/signatures?since=${encodeURIComponent(since)}`);
		signatures = data.signatures;
		// Distinct traces with ANY signature — a trace hitting several signatures
		// counts once. NEVER the sum of per-signature counts (that double-counts).
		tracesAffected = data.total_traces_affected ?? 0;
	} catch (err) {
		if (err instanceof GatewayError) {
			return (
				<>
					<WarmingBanner />
					<EmptyState
						title="No known failure patterns matched yet."
						description="Signatures appear here once a request matches a known failure pattern."
					/>
				</>
			);
		}
		throw err;
	}

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
			{/* 2 stat tiles — detection volume, never a prevention claim. Traces
			    affected is the gateway's DISTINCT count (never a sum). NO "From
			    network" tile (cross-tenant signal is V1.1). */}
			<div className="grid grid-cols-2 gap-4 sm:max-w-md">
				<StatCard
					label="Signatures matched · 30d"
					value={matched.toLocaleString()}
					hint="Live-detected AFT-1 failure patterns matched in the last 30 days. V1.1 roadmap entries are listed separately below."
				/>
				<StatCard
					label="Traces affected · 30d"
					value={tracesAffected.toLocaleString()}
					hint="Distinct traces with at least one live failure signature — never a sum of per-signature counts."
				/>
			</div>

			{/* LIVE TABLE — only signatures with a shipped reference detector. */}
			{matched === 0 ? (
				<EmptyState
					title="No known failure patterns matched in the last 30 days."
					description="When a request matches a known AFT-1 failure pattern (e.g. a tool-schema violation), it shows up here with your occurrence count, affected traces, and its AFT-1 id."
				/>
			) : (
				<div className="overflow-x-auto rounded-lg border border-line">
					<table className="w-full text-sm">
						<thead className="bg-surface-2/50">
							<HeadRow />
						</thead>
						<tbody className="divide-y divide-line">
							{live.map((s) => (
								<SignatureRow key={s.signature_id} sig={s} />
							))}
						</tbody>
					</table>
				</div>
			)}

			{/* ROADMAP SECTION — V1.1 taxonomy entries whose detector hasn't shipped.
			    Shown only when the API response includes roadmap ids (demo seeder may
			    emit them). Counts shown as-is but clearly framed as roadmap data.
			    In production with no demo seeder these ids produce zero hits and this
			    section does not render. */}
			{roadmapHits.length > 0 && (
				<section className="space-y-3 border-t border-line pt-6">
					<div>
						<h2 className="text-base font-semibold text-ink">
							Roadmap — V1.1 · detectors ship next
						</h2>
						<p className="mt-0.5 text-sm text-ink-3">
							These are valid AFT-1 taxonomy entries whose reference detector
							ships in V1.1 — not detected live yet.
						</p>
					</div>
					<div className="overflow-x-auto rounded-lg border border-line border-dashed">
						<table className="w-full text-sm">
							<thead className="bg-surface-2/30">
								<RoadmapHeadRow />
							</thead>
							<tbody className="divide-y divide-line">
								{roadmapHits.map((s) => (
									<RoadmapRow key={s.signature_id} sig={s} />
								))}
							</tbody>
						</table>
					</div>
				</section>
			)}
		</div>
	);
}

// Queries ClickHouse (via the gateway) at request time — never prerender.
export const dynamic = "force-dynamic";

export default function SignaturesPage() {
	return (
		<main className="mx-auto max-w-7xl p-6">
			<div className="mb-6">
				<h1 className="text-2xl font-semibold text-ink">Failure Signatures</h1>
				<p className="mt-1 max-w-2xl text-sm text-ink-2">
					Live-detected failures from your agents, matched against the AFT-1
					taxonomy — each with its canonical AFT-1 id, your per-tenant
					occurrence counts, and the traces it affected. V1.1 roadmap entries
					are listed in a separate section below. The cross-customer network
					signal is on the V1.1 roadmap.
				</p>
			</div>
			<Suspense fallback={<SignaturesSkeleton />}>
				<SignaturesData />
			</Suspense>
		</main>
	);
}
