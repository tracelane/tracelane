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
 *
 * ── ON THE SHARED TABLE SYSTEM (P1, 2026-08-22) ─────────────────────────────
 * The hand-rolled `<table>` this file carried is gone; it now renders
 * `Table/THead/TBody/TR/TH/TD/TDetail` from `@tracelanedev/ui`. That is where the
 * alignment rule lives, and this table was breaking it in the way that matters
 * most for a data table: the three numeric columns each restated their own
 * `text-right font-mono tabular-nums`, and the p95 column had drifted to a
 * different ink tone than the two beside it. `TD numeric` supplies all three at
 * once so a column of figures cannot lose one of them.
 *
 * NO METRIC CHANGED HERE. Every value, sort comparator, link target, `aria-*`
 * and title string is the one that was already rendering; only the class strings
 * and the row/detail markup moved.
 */
"use client";

import {
	ACTION_LABEL,
	RAIL_ROSTER,
	RAIL_TIER,
	type RailAction,
	railMeta,
} from "@/lib/guardrail-rails";
import {
	Badge,
	type BadgeProps,
	Card,
	TBody,
	TD,
	TDetail,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
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

/**
 * Action → badge tone. `redact` moved from `info` to `neutral` (P1, 2026-08-22)
 * so the whole product speaks ONE badge grammar: danger = it stopped something,
 * warn = it flagged something you should look at, neutral = it recorded
 * something. Both tokens are grey — `--info-soft` and `--surface-2` are four
 * values apart — so this is a consistency fix, not a change in what a redaction
 * means. The ACTION LABEL ("Redacts") is untouched, and it is the label that
 * carries the meaning.
 */
const ACTION_TONE: Record<RailAction, NonNullable<BadgeProps["tone"]>> = {
	block: "danger",
	redact: "neutral",
	warn: "warn",
};

/* LockIcon removed: the padlock asserted "you do not have this", which this
   component cannot know. See the note on `quietAdvanced` below. */

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
		// `numeric` on the header is what keeps it over the right-aligned figures
		// it labels. `aria-sort` is new and is the only behavioural addition in this
		// file: the control was already there and already keyboard-reachable, but a
		// screen reader had no way to learn which column was sorted or in which
		// direction — the ▼/▲ glyph is `aria-hidden` decoration by construction.
		<TH
			numeric
			aria-sort={
				active ? (sort?.dir === "desc" ? "descending" : "ascending") : "none"
			}
		>
			<button
				type="button"
				onClick={() => onSort(col)}
				// `tracking-wide` was dropped, `uppercase` deliberately KEPT, and the
				// asymmetry is the point.
				//   · TRACKING: the `<th>` carries `.t-metric-label` (from the shared
				//     `TH`), which tracks at 0.08em. Tailwind's preflight sets
				//     `letter-spacing: inherit` on `button`, so the button picks that
				//     up — restating a utility's own tracking here made a SORTABLE
				//     header letter-space differently from a static one in the same row.
				//   · CASE: preflight does NOT set `text-transform: inherit`, and the HTML
				//     rendering spec's form-control block resets `text-transform` on
				//     controls. Relying on inheritance for the case would make the label
				//     render lowercase on any engine that applies that reset, so it stays
				//     stated at the site.
				className="inline-flex items-center gap-1 uppercase hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
			>
				{label}
				<span aria-hidden className="text-ink-3">
					{active ? (sort?.dir === "desc" ? "▼" : "▲") : "↕"}
				</span>
			</button>
		</TH>
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
		// `Card quiet` — flat, not lifted. A table is a structured surface the
		// reader scans, not an object floating in front of the page, and the shadow
		// on a full-width panel reads as a seam rather than as elevation. `p-0` +
		// `overflow-hidden` let the sunken header band run edge to edge inside the
		// card's own radius.
		<Card quiet className="overflow-hidden p-0">
			<Table>
				{/* `border-t-0`: the shared `THead` is bordered top AND bottom so it holds
				    its edge "whether or not the table starts at the top of its card"
				    (its own words). This one DOES start at the top of a card, so its
				    top border lands 1px inside the card's border in the same `--line`
				    colour — two hairlines reading as one 2px rule along the top edge
				    only, heavier than the three edges around it. Suppressed here, at
				    the call site, rather than in the primitive: a table that starts
				    mid-card still wants the border, and this is a question for one
				    shared change rather than three concurrent ones. */}
				<THead className="border-t-0">
					<TR>
						<TH className="w-10 px-2" aria-label="Expand" />
						<TH>Rail</TH>
						<TH>Action</TH>
						<SortTh
							label="Evaluations"
							col="evaluations"
							sort={sort}
							onSort={onSort}
						/>
						<SortTh label="Blocked" col="blocks" sort={sort} onSort={onSort} />
						<SortTh label="p95" col="p95_ms" sort={sort} onSort={onSort} />
					</TR>
				</THead>
				<TBody>
					{rows.map((r) => (
						<RailRow
							key={r.metaId}
							live={r.live}
							metaId={r.metaId}
							range={range}
						/>
					))}
				</TBody>
			</Table>
		</Card>
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
	// A gated rail with NO verdicts in this window. Note carefully what this does and
	// does not mean: it is NOT evidence the workspace lacks the entitlement.
	//
	// This component receives only `live` and `range` — no plan and no entitlement flags
	// (the web `Entitlements` interface does not even expose the per-rail guardrail flags).
	// So "gated and quiet" is indistinguishable from "gated, granted, and nothing tripped
	// it", which is the NORMAL state for clean traffic. The old copy resolved that
	// ambiguity as an upsell — a padlock and "upgrade to enable this rail" — and showed it
	// to Team/Business/Enterprise tenants for rails their plan already grants and that
	// RailGate runs on every response.
	//
	// Renamed from `locked` deliberately: the variable name was itself the assertion.
	const quietAdvanced = m.gated && !live;
	// The tier that unlocks it (ADR-064) — a real purchase path, not just "gated".
	const tier = RAIL_TIER[m.id];

	return (
		<>
			{/* KEYBOARD PATH IS THE CHEVRON, not the row. The row's `onClick` is a
			    mouse-only convenience and always has been; the focusable
			    `aria-expanded` / `aria-controls` button in the first cell is what a
			    keyboard or screen-reader user operates.
			    This carried a `biome-ignore lint/a11y/useKeyWithClickEvents` until the
			    row moved onto the shared `TR`. The suppression is GONE because biome
			    reported it as having no effect — that rule only inspects intrinsic
			    JSX elements, so an `onClick` on a component wrapper is invisible to
			    it. Worth stating rather than silently dropping the comment: the
			    lint no longer guards this, so the reason has to live in prose. */}
			<TR
				interactive
				expanded={open}
				className="align-top"
				onClick={() => setOpen((v) => !v)}
			>
				<TD className="w-10 px-2 align-middle">
					{/* The expand affordance. Kept as a real focusable button with its
					    aria wiring (the row's own onClick is mouse-only), widened from a
					    20px box to 24px so it is a usable touch target, and the glyph is
					    now the ONE chevron the verdict table also uses — rotating rather
					    than swapping ▶/▼, so the two guardrail tables open the same way. */}
					<button
						type="button"
						aria-expanded={open}
						aria-controls={detailId}
						aria-label={open ? "Hide detail" : "Show detail"}
						onClick={(e) => {
							e.stopPropagation();
							setOpen((v) => !v);
						}}
						className="grid h-6 w-6 place-items-center rounded-md text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<span
							aria-hidden
							className={`text-2xs transition-transform ${open ? "rotate-90" : ""}`}
						>
							▸
						</span>
					</button>
				</TD>
				<TD>
					<div className="flex items-center gap-2">
						<span
							className={`font-medium ${quietAdvanced ? "text-ink-2" : "text-ink"}`}
						>
							{m.name}
						</span>
						{/* THE TIER CHIP IS A `<Badge>` NOW (verifier, 2026-08-22). It was a
						    hand-rolled `inline-flex … rounded bg-surface-2 px-1.5 py-0.5
						    t-metric-label` span, and the divergence was measurable against
						    the real `<Badge>` two cells to its right IN THE SAME ROW:
						    20px tall vs 17px, radius 3.64px vs 5.46px, padding 5.46px vs
						    7.28px, and `t-metric-label`'s 600-weight UPPERCASE against the
						    badge's 500-weight sentence case. Two chip grammars in one row
						    is the exact divergence a shared Badge exists to prevent, and a
						    600/uppercase chip also reads HEAVIER than the status badge
						    beside it — inverting the hierarchy, since the plan tier is an
						    aside and the rail's action is the row's subject.
						    `tone="neutral"` is not a change of colour: `bg-surface-2` +
						    `t-metric-label`'s `--ink-2` is byte-identical to what that
						    tone resolves to in both themes. */}
						{quietAdvanced && (
							<Badge
								tone="neutral"
								title={
									tier
										? `Advanced rail, included from the ${tier} plan. No verdicts in this window — that is the normal state for clean traffic, not a sign it is off. If your plan includes it, it is running.`
										: "Advanced rail, enabled per workspace entitlement. No verdicts in this window."
								}
							>
								{tier ?? "Advanced"}
							</Badge>
						)}
					</div>
					{/* The ledger id stays a secondary MONO line under the plain name —
					    left column, monospace, never right-aligned: it is an identifier,
					    not a number. */}
					<span className="font-mono text-2xs text-ink-3">{m.id}</span>
				</TD>
				<TD>
					<Badge tone={ACTION_TONE[m.action]}>{ACTION_LABEL[m.action]}</Badge>
					<span className="ml-1 text-2xs uppercase tracking-wide text-ink-3">
						{m.side === "both" ? "req+resp" : m.side}
					</span>
				</TD>
				<TD numeric>{live ? live.evaluations.toLocaleString() : "—"}</TD>
				<TD numeric>
					{/* The link inherits mono + tabular-nums from the `numeric` cell, so
					    it no longer restates them and cannot drift from its column. */}
					{live && live.blocks > 0 ? (
						<Link
							href={blockHref(range)}
							onClick={(e) => e.stopPropagation()}
							title="See the blocked verdicts →"
							className="text-danger-ink underline decoration-danger/30 underline-offset-2 hover:decoration-danger focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						>
							{live.blocks.toLocaleString()}
						</Link>
					) : live ? (
						<span className="text-ink-3">0</span>
					) : (
						<span className="text-ink-3">—</span>
					)}
				</TD>
				<TD numeric muted>
					{live ? `${live.p95_ms.toLocaleString()} ms` : "—"}
				</TD>
			</TR>

			{open && (
				<TDetail id={detailId} colSpan={6}>
					<div className="max-w-3xl space-y-2 text-sm">
						<p className="text-ink-2">{m.blurb}</p>
						{quietAdvanced && (
							<p className="text-xs text-ink-3">
								Advanced rail — no activity in this window. Absence of verdicts
								does not mean the rail is not entitled; enable per workspace.
							</p>
						)}
						{live && live.fail_opens > 0 && (
							<p className="text-xs text-warn-ink">
								{live.fail_opens.toLocaleString()} verdict
								{live.fail_opens === 1 ? "" : "s"} failed open (the rail errored
								and the request proceeded).
							</p>
						)}
					</div>
				</TDetail>
			)}
		</>
	);
}
