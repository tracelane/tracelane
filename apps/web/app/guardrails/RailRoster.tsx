/**
 * RailRoster — the full 9-rail guardrail surface, live stats merged onto the
 * honest roster (lib/guardrail-rails). Every rail shows its plain name, the exact
 * action it takes (Blocks / Redacts / Warns — never inferred from the id), and
 * its real counts when it produced verdicts. Gated rails with no verdicts show as
 * honest "Advanced" (locked) rows so the page shows the WHOLE surface, not only
 * the free rails that happened to fire.
 *
 * A rail's Blocked count links to the verdict-detail list (decision=block) — the
 * honest target: a blocked request 403s pre-span so there is no trace to link to,
 * but the verdict IS recorded (which rails fired, reason codes, when). We do NOT
 * link to a trace list (verdicts are keyed by correlation_id, not span trace_id).
 */
"use client";

import {
	ACTION_LABEL,
	RAIL_ROSTER,
	RAIL_TIER,
	type RailAction,
	railMeta,
} from "@/lib/guardrail-rails";
import { Badge } from "@tracelanedev/ui";
import Link from "next/link";
import { useId, useMemo, useState } from "react";

/** Verdict-detail list for blocked verdicts, preserving the active range. */
function blockHref(range?: string): string {
	return range
		? `/guardrails/verdicts?decision=block&range=${range}`
		: "/guardrails/verdicts?decision=block";
}

export interface LiveRail {
	rail: string;
	evaluations: number;
	blocks: number;
	block_rate_pct: number;
	fail_opens: number;
	fail_open_rate_pct: number;
	p95_ms: number;
}

/** Numeric columns the roster can be sorted by (the LiveRail keys). */
type SortKey = "evaluations" | "blocks" | "p95_ms";
type SortState = { key: SortKey; dir: "asc" | "desc" };

const ACTION_TONE: Record<RailAction, "danger" | "info" | "warn"> = {
	block: "danger",
	redact: "info",
	warn: "warn",
};

function LockIcon() {
	return (
		<svg
			viewBox="0 0 16 16"
			width="11"
			height="11"
			fill="none"
			stroke="currentColor"
			strokeWidth="1.6"
			aria-hidden="true"
			className="shrink-0"
		>
			<rect x="3.5" y="7" width="9" height="6.5" rx="1.2" />
			<path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
		</svg>
	);
}

/** A sortable numeric column header — toggles desc↔asc, arrow shows state. */
function SortTh({
	label,
	col,
	sort,
	onSort,
}: {
	label: string;
	col: SortKey;
	sort: SortState | null;
	onSort: (c: SortKey) => void;
}) {
	const active = sort?.key === col;
	return (
		<th className="px-3 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
			<button
				type="button"
				onClick={() => onSort(col)}
				className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
			>
				{label}
				<span className="text-ink-3">
					{active ? (sort?.dir === "desc" ? "▼" : "▲") : "↕"}
				</span>
			</button>
		</th>
	);
}

export function RailRoster({
	live,
	range,
}: { live: LiveRail[]; range?: string }) {
	const byId = useMemo(() => new Map(live.map((r) => [r.rail, r])), [live]);
	const [sort, setSort] = useState<SortState | null>(null);

	const onSort = (col: SortKey) =>
		setSort((s) =>
			s?.key === col
				? { key: col, dir: s.dir === "desc" ? "asc" : "desc" }
				: { key: col, dir: "desc" },
		);

	// The full 9-rail roster is always present (not paginated), so sorting the
	// complete in-memory set is honest — not a client-only illusion of a page.
	// Default = the curated roster order; rails with no live verdicts always sink
	// to the bottom when a numeric column is sorted (they have no number to rank).
	const rows = useMemo(() => {
		const base = RAIL_ROSTER.map((m) => ({
			metaId: m.id,
			live: byId.get(m.id),
		}));
		if (!sort) return base;
		return [...base].sort((a, b) => {
			const av = a.live ? a.live[sort.key] : null;
			const bv = b.live ? b.live[sort.key] : null;
			if (av === null && bv === null) return 0;
			if (av === null) return 1;
			if (bv === null) return -1;
			return sort.dir === "desc" ? bv - av : av - bv;
		});
	}, [byId, sort]);

	return (
		<div className="overflow-x-auto rounded-lg border border-line">
			<table className="w-full text-sm">
				<thead className="bg-surface-2/50">
					<tr>
						<th className="w-8 py-3 pl-4" aria-label="Expand" />
						<th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Rail
						</th>
						<th className="px-3 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Action
						</th>
						<SortTh
							label="Evaluations"
							col="evaluations"
							sort={sort}
							onSort={onSort}
						/>
						<SortTh label="Blocked" col="blocks" sort={sort} onSort={onSort} />
						<SortTh label="p95" col="p95_ms" sort={sort} onSort={onSort} />
					</tr>
				</thead>
				<tbody className="divide-y divide-line">
					{rows.map((r) => (
						<RailRow
							key={r.metaId}
							live={r.live}
							metaId={r.metaId}
							range={range}
						/>
					))}
				</tbody>
			</table>
		</div>
	);
}

function RailRow({
	live,
	metaId,
	range,
}: { live?: LiveRail; metaId: string; range?: string }) {
	const [open, setOpen] = useState(false);
	const detailId = useId();
	const m = railMeta(metaId);
	// "Locked" = a gated rail that produced no verdicts for this tenant. A gated
	// rail WITH verdicts is enabled → show it as active.
	const locked = m.gated && !live;
	// The tier that unlocks it (ADR-064) — a real purchase path, not just "gated".
	const tier = RAIL_TIER[m.id];

	return (
		<>
			{/* biome-ignore lint/a11y/useKeyWithClickEvents: the chevron button is the keyboard toggle; the row onClick is a mouse-only convenience. */}
			<tr
				className="cursor-pointer align-top transition-colors hover:bg-surface-2/30"
				onClick={() => setOpen((v) => !v)}
			>
				<td className="py-3 pl-4 pr-1">
					<button
						type="button"
						aria-expanded={open}
						aria-controls={detailId}
						aria-label={open ? "Hide detail" : "Show detail"}
						onClick={(e) => {
							e.stopPropagation();
							setOpen((v) => !v);
						}}
						className="grid h-5 w-5 place-items-center rounded text-ink-3 outline-none transition-colors hover:text-ink focus-visible:ring-2 focus-visible:ring-seal"
					>
						<span aria-hidden className="text-[9px]">
							{open ? "▼" : "▶"}
						</span>
					</button>
				</td>
				<td className="px-3 py-3">
					<div className="flex items-center gap-2">
						<span
							className={`font-medium ${locked ? "text-ink-2" : "text-ink"}`}
						>
							{m.name}
						</span>
						{locked && (
							<span
								className="inline-flex items-center gap-1 rounded bg-accent-soft px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-accent-ink"
								title={
									tier
										? `Available on the ${tier} plan — upgrade to enable this rail.`
										: "Advanced rail — enabled per workspace entitlement."
								}
							>
								<LockIcon />
								{tier ?? "Advanced"}
							</span>
						)}
					</div>
					<span className="font-mono text-[11px] text-ink-3">{m.id}</span>
				</td>
				<td className="px-3 py-3">
					<Badge tone={ACTION_TONE[m.action]}>{ACTION_LABEL[m.action]}</Badge>
					<span className="ml-1 text-[10px] uppercase tracking-wide text-ink-3">
						{m.side === "both" ? "req+resp" : m.side}
					</span>
				</td>
				<td className="px-3 py-3 text-right font-mono tabular-nums text-ink">
					{live ? live.evaluations.toLocaleString() : "—"}
				</td>
				<td className="px-3 py-3 text-right">
					{live && live.blocks > 0 ? (
						<Link
							href={blockHref(range)}
							onClick={(e) => e.stopPropagation()}
							title="See the blocked verdicts →"
							className="font-mono tabular-nums text-danger underline decoration-danger/30 underline-offset-2 hover:decoration-danger focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							{live.blocks.toLocaleString()}
						</Link>
					) : live ? (
						<span className="font-mono tabular-nums text-ink-3">0</span>
					) : (
						<span className="text-ink-3">—</span>
					)}
				</td>
				<td className="px-3 py-3 text-right font-mono tabular-nums text-ink-2">
					{live ? `${live.p95_ms.toLocaleString()} ms` : "—"}
				</td>
			</tr>

			{open && (
				<tr id={detailId} className="bg-surface-2/20">
					<td />
					<td colSpan={5} className="px-3 pb-4 pt-1">
						<div className="max-w-3xl space-y-2 text-sm">
							<p className="text-ink-2">{m.blurb}</p>
							{locked && (
								<p className="text-xs text-ink-3">
									Advanced rail — enabled per workspace entitlement; it isn't
									running for this workspace yet, so it has no verdicts to show.
								</p>
							)}
							{live && live.fail_opens > 0 && (
								<p className="text-xs text-warn">
									{live.fail_opens.toLocaleString()} verdict
									{live.fail_opens === 1 ? "" : "s"} failed open (the rail
									errored and the request proceeded).
								</p>
							)}
						</div>
					</td>
				</tr>
			)}
		</>
	);
}
