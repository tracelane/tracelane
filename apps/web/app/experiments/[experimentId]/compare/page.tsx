/**
 * `EVL-02` — the experiment diff. Two arms, one screen, regressions first.
 *
 * Server Component: the gateway owns the tenant-scoped ClickHouse read, the
 * alignment, the verdicts and the thresholds. This page renders what it returns
 * and nothing more — there is no ClickHouse client here and there must never be
 * (`apps/web/CLAUDE.md`).
 *
 * ## The two rules this page exists to honour
 *
 * **1. A regression is legible BEFORE any number is read.** Three independent
 * channels, none of them colour: position (regressions sort first, and the
 * gateway does that sorting), a TEXT marker (`▼ regressed`), and the count
 * sentence above the table. A colour-blind reader and a screen-reader user get
 * the same answer as everyone else.
 *
 * **2. Zero is not unknown.** `score = null` renders `—`; `score = 0` renders
 * `0.00`. They are different facts — one item was not measured, the other scored
 * zero — and rendering them alike manufactures a regression that did not happen
 * on the screen a release decision is made on. Every `fmt*` helper below takes
 * `null` seriously for exactly this reason.
 */

import type {
	ArmAggregate,
	ComparedItem,
	ComparedSide,
	ExperimentCompareResponse,
} from "@/app/api/experiments/route";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Compare arms — Tracelane" };

type SP = Record<string, string | undefined>;

/** `—` for unknown, two decimals for a measured value INCLUDING zero. */
function fmtScore(v: number | null): string {
	return v === null ? "—" : v.toFixed(2);
}

/** Signed score delta. `—` when either side was not measured. */
function fmtDeltaScore(v: number | null): string {
	if (v === null) return "—";
	const sign = v > 0 ? "+" : v < 0 ? "−" : "±";
	return `${sign}${Math.abs(v).toFixed(2)}`;
}

function fmtMs(v: number | null): string {
	return v === null ? "—" : `${v.toLocaleString("en-US")}ms`;
}

/** Signed latency delta, with the ratio only when there IS one. */
function fmtDeltaMs(ms: number | null, pct: number | null): string {
	if (ms === null) return "—";
	const sign = ms > 0 ? "+" : ms < 0 ? "−" : "±";
	const abs = `${sign}${Math.abs(ms).toLocaleString("en-US")}ms`;
	// pct is null when the A-side latency was 0. Show the absolute move and omit
	// the ratio rather than inventing one.
	return pct === null ? abs : `${abs} (${sign}${Math.abs(pct).toFixed(0)}%)`;
}

/**
 * Cost to the cent-and-beyond, or `—` for an unpriced model.
 *
 * **Never `$0.00` for an unknown cost.** `pricing::cost_usd` returns `None` for a
 * model whose price we do not know, and summing that as zero is the exact
 * coercion that made the spend tile under-report silently.
 */
function fmtUsd(v: number | null): string {
	return v === null ? "—" : `$${v.toFixed(4)}`;
}

function fmtPct(v: number | null): string {
	return v === null ? "—" : `${v.toFixed(1)}%`;
}

/** The verdict's TEXT marker. Never a glyph alone — see the header comment. */
const VERDICT_LABEL: Record<ComparedItem["verdict"], string> = {
	regressed: "▼ regressed",
	unknown: "? unknown",
	improved: "▲ improved",
	unchanged: "· unchanged",
	only_in_a: "+ only in A",
	only_in_b: "+ only in B",
};

function Side({ side }: { side: ComparedSide | null }) {
	if (side === null) {
		return <span className="text-ink-3">—</span>;
	}
	return <span>{fmtScore(side.score)}</span>;
}

/** One arm's header strip (spec §3a). Every `—` below is UNKNOWN, not zero. */
function ArmCard({ arm, letter }: { arm: ArmAggregate; letter: "A" | "B" }) {
	return (
		<div className="rounded-lg border border-line bg-surface-2 p-3">
			<div className="t-metric-label">
				Arm {letter}
				{arm.arm_label ? ` · ${arm.arm_label}` : ` · #${arm.ordinal}`}
			</div>
			<div className="mt-1 font-mono text-sm break-all">{arm.model || "—"}</div>
			<dl className="mt-2 space-y-1 text-sm">
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Pass rate</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{fmtPct(arm.pass_rate)}
						<span className="ml-1 text-ink-3 text-xs">
							({arm.passed}/{arm.passed + arm.failed})
						</span>
					</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Mean score</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{fmtScore(arm.mean_score)}
					</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">p95 latency</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{fmtMs(arm.p95_latency_ms)}
					</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Total cost</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{fmtUsd(arm.total_cost_usd)}
						{/* An unknown cost is its OWN number, never folded into the sum
						    as if it were zero. */}
						{arm.unpriced_items > 0 && (
							<span className="ml-1 text-ink-3 text-xs">
								+{arm.unpriced_items} unpriced
							</span>
						)}
					</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Items</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{arm.items_matched} compared
						{arm.items_run !== arm.items_matched && (
							<span className="ml-1 text-ink-3 text-xs">
								of {arm.items_run} run
							</span>
						)}
					</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Errored</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>{arm.errored}</dd>
				</div>
			</dl>
		</div>
	);
}

export default async function CompareArmsPage({
	params,
	searchParams,
}: {
	params: Promise<{ experimentId: string }>;
	searchParams: Promise<SP>;
}) {
	const { experimentId } = await params;
	const sp = await searchParams;
	const a = sp.a?.trim();
	const b = sp.b?.trim();

	if (!a || !b) {
		return (
			<main className="p-6">
				<h1 className="t-h1 mb-4">Compare arms</h1>
				<EmptyState
					title="Pick two arms to compare"
					description="Open the experiment and choose two arms, or pass ?a=<arm_id>&b=<arm_id>."
				/>
				<p className="mt-4 text-sm">
					<Link
						className="underline"
						href={`/experiments/${encodeURIComponent(experimentId)}`}
					>
						Back to the experiment
					</Link>
				</p>
			</main>
		);
	}

	let data: ExperimentCompareResponse;
	try {
		data = await gatewayGet<ExperimentCompareResponse>(
			`/v1/experiments/${encodeURIComponent(experimentId)}/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`,
		);
	} catch (err) {
		// THE STATUS IS THE ANSWER. A 409 (an arm is still running) is not a
		// failure of anything and must not read as one; a 404 is deliberately the
		// same for an unknown id and another tenant's; a 403 is the plan or the
		// role. Collapsing them into "something went wrong" is the defect that
		// made an owner-only 403 read as a generic error.
		const status = err instanceof GatewayError ? err.status : 0;
		const copy =
			status === 409
				? {
						title: "One of these arms is still running",
						description:
							"Comparing now would compare an incomplete set — every item the arm has not reached yet would read as a regression. The comparison unlocks when both arms finish.",
					}
				: status === 404
					? {
							title: "Experiment not found",
							description: "It doesn't exist in this workspace.",
						}
					: status === 403
						? {
								title: "Experiments aren't included in this plan",
								description:
									"Experiments run one dataset against several prompt versions or models and diff the results.",
							}
						: {
								title: "Couldn't load this comparison",
								description:
									"Nothing is wrong with the experiment itself — the gateway couldn't be reached. Try again.",
							};
		return (
			<main className="p-6">
				<h1 className="t-h1 mb-4">Compare arms</h1>
				<EmptyState title={copy.title} description={copy.description} />
				<p className="mt-4 text-sm">
					<Link
						className="underline"
						href={`/experiments/${encodeURIComponent(experimentId)}`}
					>
						Back to the experiment
					</Link>
				</p>
			</main>
		);
	}

	const t = data.thresholds;

	return (
		<main className="p-6">
			<h1 className="t-h1 mb-1">{data.name}</h1>
			<p className="mb-3 text-ink-3 text-sm">
				dataset{" "}
				<span className="font-mono">{data.dataset_id.slice(0, 8)}…</span> ·
				snapshot{" "}
				<span className="font-mono">{data.snapshot_id.slice(0, 8)}…</span> ·{" "}
				{data.item_count} item{data.item_count === 1 ? "" : "s"}
			</p>

			{/* THE SENTENCE, in words, before any number is read. Built by the
			    gateway so this page and the API cannot disagree about it. */}
			<p className="mb-1 font-medium text-sm">{data.summary}</p>
			<p className="mb-4 text-ink-3 text-xs">
				▼ regressed = score down ≥{t.score_delta_min.toFixed(2)}, or pass →
				fail. ▲/▼ latency fires only above BOTH {t.latency_delta_min_ms}ms and{" "}
				{t.latency_delta_min_pct}%.
			</p>

			{/* A PARTIAL comparison must never read as a complete one. */}
			{data.partial_note && (
				<p className="mb-4 rounded-lg border border-line bg-surface-2 p-3 text-sm">
					{data.partial_note}
				</p>
			)}

			<div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
				<ArmCard arm={data.a} letter="A" />
				<ArmCard arm={data.b} letter="B" />
			</div>

			<div className="overflow-x-auto">
				<table className="w-full text-sm">
					<thead>
						<tr className="border-line border-b text-left">
							<th className="px-3 py-1.5">Item</th>
							<th className="px-3 py-1.5 text-right">A</th>
							<th className="px-3 py-1.5 text-right">B</th>
							<th className="px-3 py-1.5 text-right">Δ score</th>
							<th className="px-3 py-1.5 text-right">Δ latency</th>
							<th className="px-3 py-1.5 text-right">Δ cost</th>
							<th className="px-3 py-1.5">Verdict</th>
						</tr>
					</thead>
					<tbody>
						{data.rows.map((r) => (
							<tr
								key={`${r.dataset_item_id ?? "ord"}-${r.item_ordinal}`}
								className="border-line border-b"
							>
								<td className="px-3 py-2">
									<div className="truncate">{r.label || "(unnamed)"}</div>
									{/* The error text INLINE on the row, not behind a hover:
									    an unknown verdict is actionable and the reason is the
									    action. */}
									{r.a?.error && (
										<div className="text-ink-3 text-xs">
											A errored: {r.a.error}
										</div>
									)}
									{r.b?.error && (
										<div className="text-ink-3 text-xs">
											B errored: {r.b.error}
										</div>
									)}
									{(r.a?.output_truncated || r.b?.output_truncated) && (
										<div className="text-ink-3 text-xs">
											… output truncated at 8 KB
										</div>
									)}
								</td>
								<td
									className="px-3 py-2 text-right font-mono"
									style={{ fontVariantNumeric: "tabular-nums" }}
								>
									<Side side={r.a} />
								</td>
								<td
									className="px-3 py-2 text-right font-mono"
									style={{ fontVariantNumeric: "tabular-nums" }}
								>
									<Side side={r.b} />
								</td>
								<td
									className="px-3 py-2 text-right font-mono"
									style={{ fontVariantNumeric: "tabular-nums" }}
								>
									{fmtDeltaScore(r.delta_score)}
								</td>
								<td
									className="px-3 py-2 text-right font-mono"
									style={{ fontVariantNumeric: "tabular-nums" }}
								>
									{fmtDeltaMs(r.delta_latency_ms, r.delta_latency_pct)}
									{r.latency_slower && (
										<span className="ml-1 text-xs">▲ slower</span>
									)}
									{r.latency_faster && (
										<span className="ml-1 text-xs">▼ faster</span>
									)}
								</td>
								<td
									className="px-3 py-2 text-right font-mono"
									style={{ fontVariantNumeric: "tabular-nums" }}
								>
									{fmtUsd(r.delta_cost_usd)}
									{r.cost_higher && <span className="ml-1 text-xs">▲</span>}
									{r.cost_lower && <span className="ml-1 text-xs">▼</span>}
								</td>
								<td className="px-3 py-2 whitespace-nowrap">
									{VERDICT_LABEL[r.verdict]}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>

			{/* The six counts, so a reader can add them up and get the row count —
			    the cheapest possible check that this surface is not lying. */}
			<p className="mt-3 text-ink-3 text-xs">
				{data.regressed_count} regressed · {data.unknown_count} unknown ·{" "}
				{data.improved_count} improved · {data.unchanged_count} unchanged ·{" "}
				{data.only_in_a} only in A · {data.only_in_b} only in B ={" "}
				{data.rows.length} rows
			</p>

			<p className="mt-4 text-sm">
				<Link
					className="underline"
					href={`/experiments/${encodeURIComponent(experimentId)}`}
				>
					Back to the experiment
				</Link>
			</p>
		</main>
	);
}
