import { fmtDurationMs, fmtUsd } from "@/lib/metrics/format";
import { PageHeader } from "@tracelanedev/ui";
import { RunComparisonPicker } from "./RunComparisonPicker";
/**
 * `EVL-02` — one experiment: its arms, and the way into the diff.
 *
 * Server Component. The gateway owns the read and computes every aggregate; this
 * page renders them. `comparable` is decided by the gateway too — a client that
 * re-derived "are both arms terminal" from five status strings would be a second
 * copy of a rule that must not drift.
 *
 * **A running arm keeps its numbers on screen and shows `n / item_count`.** It is
 * never replaced by a spinner: an experiment takes minutes, and a spinner for
 * four minutes is indistinguishable from a hang.
 */

import type {
	ArmAggregate,
	ExperimentDetail,
} from "@/app/api/experiments/route";
import { formatDateTimeUtc } from "@/lib/format-date";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Experiment — Tracelane" };

function fmtScore(v: number | null): string {
	return v === null ? "—" : v.toFixed(2);
}
function fmtPct(v: number | null): string {
	return v === null ? "—" : `${v.toFixed(1)}%`;
}
const fmtMs = fmtDurationMs;

/** Plain words. A status glyph alone does not survive a screen reader. */
const ARM_STATUS_COPY: Record<ArmAggregate["status"], string> = {
	pending: "queued — arms run one after another",
	running: "running",
	passed: "passed",
	failed: "failed",
	errored: "errored",
};

function ArmRow({
	arm,
	letter,
	itemCount,
}: {
	arm: ArmAggregate;
	letter: string;
	itemCount: number;
}) {
	return (
		<div className="rounded-card border border-line bg-surface-2 p-3">
			<div className="flex items-baseline justify-between gap-3">
				<div className="t-metric-label">
					Arm {letter}
					{arm.arm_label ? ` · ${arm.arm_label}` : ""}
				</div>
				<div className="text-ink-3 text-xs">{ARM_STATUS_COPY[arm.status]}</div>
			</div>
			<div className="mt-1 font-mono text-sm break-all">{arm.model || "—"}</div>
			<div className="mt-1 font-mono text-2xs text-ink-3 break-all">
				version {arm.prompt_version_id.slice(0, 8)}…
			</div>
			<dl className="mt-2 space-y-1 text-sm">
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Items</dt>
					{/* `41 / 50` — the numerator is what ran, the denominator is the
					    FROZEN snapshot. Rendering the numerator alone would let a run
					    that stopped early read as complete. */}
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{arm.items_run} / {itemCount}
					</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Pass rate</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{fmtPct(arm.pass_rate)}
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
					<dt className="text-ink-3">Cost</dt>
					<dd style={{ fontVariantNumeric: "tabular-nums" }}>
						{fmtUsd(arm.total_cost_usd)}
						{arm.unpriced_items > 0 && (
							<span className="ml-1 text-ink-3 text-xs">
								+{arm.unpriced_items} unpriced
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

export default async function ExperimentDetailPage({
	params,
}: {
	params: Promise<{ experimentId: string }>;
}) {
	const { experimentId } = await params;

	let data: ExperimentDetail;
	try {
		data = await gatewayGet<ExperimentDetail>(
			`/v1/experiments/${encodeURIComponent(experimentId)}`,
		);
	} catch (err) {
		const status = err instanceof GatewayError ? err.status : 0;
		const copy =
			status === 404
				? {
						title: "Experiment not found",
						description: "It doesn't exist in this workspace.",
					}
				: status === 403
					? {
							title: "Experiments aren't included in this plan",
							description:
								"Experiments run one dataset against several prompt versions or models and diff the results, so a change ships only when it measurably wins.",
						}
					: {
							title: "Couldn't load this experiment",
							description:
								"Nothing is wrong with the experiment itself — the gateway couldn't be reached. Try again.",
						};
		return (
			<div className="p-6">
				<PageHeader title={<>Experiment</>} />
				<EmptyState title={copy.title} description={copy.description} />
				<p className="mt-4 text-sm">
					<Link className="underline" href="/experiments">
						Back to experiments
					</Link>
				</p>
			</div>
		);
	}

	// The compare view diffs exactly TWO arms. Default to the first two, which is
	// what a 2-arm experiment — the common case — wants with no selection at all.

	return (
		<div className="p-6">
			<div className="mb-1 flex flex-wrap items-center justify-between gap-3">
				<PageHeader title={data.name} />
				<a
					className="text-sm underline"
					href={`/experiments/${encodeURIComponent(experimentId)}`}
				>
					Refresh results
				</a>
			</div>
			<p className="mb-4 text-ink-3 text-sm">
				dataset{" "}
				<span className="font-mono">{data.dataset_id.slice(0, 8)}…</span> ·
				snapshot{" "}
				<span className="font-mono">{data.snapshot_id.slice(0, 8)}…</span> ·{" "}
				{data.item_count} item{data.item_count === 1 ? "" : "s"} · {data.status}{" "}
				· started{" "}
				{formatDateTimeUtc(new Date(data.created_at_ms).toISOString())}
			</p>

			{data.notes && (
				<p className="mb-4 rounded-card border border-line bg-surface-2 p-3 text-sm">
					{data.notes}
				</p>
			)}

			<div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
				{data.arms.map((arm, i) => (
					<ArmRow
						key={arm.arm_id}
						arm={arm}
						letter={String.fromCharCode(65 + i)}
						itemCount={data.item_count}
					/>
				))}
			</div>

			<RunComparisonPicker experimentId={experimentId} arms={data.arms} />

			<p className="mt-4 text-sm">
				<Link className="underline" href="/experiments">
					Back to experiments
				</Link>
			</p>
		</div>
	);
}
