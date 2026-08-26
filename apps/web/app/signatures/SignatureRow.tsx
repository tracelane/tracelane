/**
 * SignatureRow — one live AFT-1 detection, expandable to its evidence story.
 *
 * `spans.aft_ids` carries the CANONICAL AFT-1 id, so `sig.signature_id` IS the
 * canonical id (one vocabulary — see aft-taxonomy.ts). Summary columns:
 * Signature (name) | AFT-1 id | Severity | Occurrences | Traces | First/Last seen.
 *
 * This component is used ONLY for live-detected signatures (detectorStatus ===
 * "live"). Roadmap taxonomy entries are split out in page.tsx and rendered in
 * their own simpler section — never routed through this component. That keeps
 * the expanded view honest: description, detection method, affected-traces link,
 * and audit-ledger note are all real live-detector evidence.
 *
 * ── ON THE SHARED TABLE SYSTEM (P1, 2026-08-22) ─────────────────────────────
 * Every cell is now `TD` from `@tracelanedev/ui`, so this row shares one height,
 * one hover, one header band and ONE ALIGNMENT RULE with every other table in
 * the app. Concretely: `numeric` (right + tabular + mono, all three together) on
 * Occurrences and Traces; `mono` on the two technical LEFT columns (the AFT-1 id
 * and the timestamps); plain text on the name. `TR interactive expanded` +
 * `TDetail` replace the hand-rolled hover/`bg-surface-2` pair.
 *
 * ── THE ID IS PRINTED ONCE, NOT TWICE ───────────────────────────────────────
 * The Signature cell used to repeat `sig.signature_id` in mono under the name
 * while the very next column rendered the same string inside a chip. Nothing is
 * lost by printing it once: the name column carries the NAME, the AFT-1 column
 * carries the ID. That collapses a two-line cell to one line, which is most of
 * the density win here — a table of 13 signatures is now 13 rows tall, not 26.
 *
 * ── MAPPED vs UNMAPPED READS AT A GLANCE, WITH NO HUE ───────────────────────
 * This column used to be `Badge tone="info"` for an id that resolves in the AFT-1
 * taxonomy and `tone="neutral"` for one that does not, in ADJACENT ROWS. Badge.tsx
 * measured what that actually looks like since `--info` became a chart neutral:
 * the two FILLS are four values apart (#f1f1f0 vs #f5f5f4 — invisible) and the
 * distinction survives only in ink weight (15.7:1 vs 4.89:1). Reading a
 * near-black chip against a mid-grey chip is not "at a glance"; it is a contrast
 * comparison the reader has to make between two rows.
 *
 * THE FIX INVERTS WHICH CASE CARRIES THE MARK, rather than reaching for a colour.
 * A mapped id is the NORM, so it is bare mono text. An unmapped id is the
 * ANOMALY, so it carries a small `unmapped` chip. The distinction is then
 * presence-of-a-chip plus a WORD — legible in both themes, in greyscale, and to
 * a screen reader, with no contrast measurement involved and no second hue in a
 * monochrome system. It also deletes a chip from every normal row, which is the
 * chip-wall the P0 brief bans.
 *
 * Badge.tsx's own note proposes "a deeper WELL for `info`" as the alternative.
 * That is a change to a SHARED primitive and is reported rather than made here.
 *
 * Colour discipline (P0, 2026-08-22): names are INK; red is reserved for a real
 * Block severity. Links use --action-ink, which is the ink family rather than a
 * brand accent. Severity is the row's ONE chip.
 */
"use client";

import { aftFor } from "@/lib/aft-taxonomy";
import { absoluteDate } from "@/lib/format-date";
import { Badge, TD, TDetail, TR, cn } from "@tracelanedev/ui";
import Link from "next/link";
import { useId, useState } from "react";

export type SignatureHit = {
	signature_id: string;
	your_hits: number;
	action: "blocking" | "flag-only";
	/** RFC3339 UTC of the first/most-recent span that hit this signature. */
	first_seen: string;
	last_seen: string;
	/** Distinct traces this signature appears in. */
	traces_affected: number;
};

/**
 * Column count of the live-signatures table. `TDetail` requires an explicit
 * `colSpan` and deliberately does not default one — a wrong span silently breaks
 * the column grid for the whole table — so the header (page.tsx) and the detail
 * panel (here) read the SAME constant rather than two hand-counted literals.
 */
export const SIGNATURE_TABLE_COLS = 8;

/** AFT-1 intervention type (observe-first): Block would halt under enforcement. */
function severity(action: SignatureHit["action"]): {
	label: string;
	tone: "danger" | "warn";
} {
	return action === "blocking"
		? { label: "Block", tone: "danger" }
		: { label: "Warn", tone: "warn" };
}

/**
 * The disclosure chevron. An SVG that ROTATES rather than a `▶`/`▼` glyph swap:
 * the two glyphs are different shapes at different optical weights, so the old
 * affordance flickered between two marks instead of turning. `currentColor` at
 * stroke 1.6 matches MetricIcon's line weight, so it belongs to the same icon
 * language as the rest of the system.
 */
function Chevron({ open }: { open: boolean }) {
	return (
		<svg
			aria-hidden="true"
			role="presentation"
			width="12"
			height="12"
			viewBox="0 0 12 12"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className={cn("transition-transform duration-150", open && "rotate-90")}
		>
			<path d="M4.5 2.5 L8 6 L4.5 9.5" />
		</svg>
	);
}

export function SignatureRow({ sig }: { sig: SignatureHit }) {
	const [open, setOpen] = useState(false);
	const detailId = useId();
	const t = aftFor(sig.signature_id);
	const name = t?.name ?? sig.signature_id;
	const sev = severity(sig.action);
	// range=30d so the destination window matches the 30-day signature aggregate
	// (the traces list now defaults to 24h, which would show fewer rows than the count).
	const tracesHref = `/traces?signature_id=${encodeURIComponent(sig.signature_id)}&range=30d`;
	// Does the detail panel have any taxonomy FIELDS above its action footer?
	// False for an id that does not resolve — see the footer's comment.
	const hasFields = Boolean(t?.description || t?.detection);

	return (
		<>
			{/* The row's onClick is a MOUSE-ONLY convenience; the keyboard path is the
			    focusable chevron button in the first cell (aria-expanded /
			    aria-controls). This carried a `biome-ignore
			    lint/a11y/useKeyWithClickEvents` suppression, which biome now reports as
			    having NO EFFECT: the rule inspects intrinsic DOM elements, and `TR` is a
			    component, so nothing was ever being suppressed. The RATIONALE is kept —
			    the a11y obligation is real whether or not a linter can see it — and the
			    dead directive is removed rather than left to read as a passing check. */}
			<TR
				interactive
				expanded={open}
				className="group"
				onClick={() => setOpen((v) => !v)}
			>
				{/* DISCLOSURE — a real button, the keyboard-accessible toggle. The cell
				    overrides `TD`'s `px-4` to `px-2`: the chevron is furniture, not a
				    column of data, and 16px of gutter either side of a 12px mark pushed
				    the first real column a third of an inch off the card edge. */}
				<TD className="w-10 px-2">
					<button
						type="button"
						aria-expanded={open}
						aria-controls={detailId}
						aria-label={open ? "Hide detail" : "Show detail"}
						onClick={(e) => {
							e.stopPropagation();
							setOpen((v) => !v);
						}}
						// `text-ink-3` at rest, `--ink` once the pointer is anywhere on the
						// row (`group-hover`) — so the affordance announces itself for the
						// WHOLE row rather than only when the pointer finds the 24px mark.
						// The `--surface-2` well on direct hover is the same inert chip
						// every other icon in the system sits in.
						className="grid h-6 w-6 place-items-center rounded-md text-ink-3 transition-colors group-hover:text-ink hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<Chevron open={open} />
					</button>
				</TD>

				{/* SIGNATURE — the NAME, in ink. The canonical id is the next column;
				    printing it here too was the same string twice in one row. */}
				<TD className="font-medium">{name}</TD>

				{/* AFT-1 — the canonical id as bare mono text (the norm), with an
				    `unmapped` chip when the id does not resolve in the taxonomy (the
				    anomaly). See the header for why the mark is on the exception. */}
				<TD mono muted className="whitespace-nowrap text-xs">
					{t ? (
						<span title={`${t.name} — ${t.detection}  ·  AFT-1 taxonomy (CC0)`}>
							{sig.signature_id}
						</span>
					) : (
						<span
							className="inline-flex items-center gap-2"
							title="This id is not in the AFT-1 taxonomy map — unmapped detection."
						>
							{sig.signature_id}
							{/* `font-sans`: the chip inherits `font-mono` from the cell, and
							    "unmapped" is a WORD, not a technical value. */}
							<Badge tone="neutral" className="font-sans">
								unmapped
							</Badge>
						</span>
					)}
				</TD>

				{/* SEVERITY — AFT-1 intervention type (observe-first: recorded, not enforced) */}
				<TD>
					<Badge
						tone={sev.tone}
						title="AFT-1 intervention type · observe-first — the decision is recorded, not enforced."
					>
						{sev.label}
					</Badge>
				</TD>

				{/* OCCURRENCES — `numeric`: right + tabular + mono, all three together. */}
				<TD numeric>{sig.your_hits.toLocaleString()}</TD>

				{/* TRACES — the functional link to the affected traces (--action-ink),
				    in the same `numeric` column treatment so the two count columns
				    share a decimal position. */}
				<TD numeric>
					<Link
						href={tracesHref}
						onClick={(e) => e.stopPropagation()}
						className="font-medium text-action-ink hover:underline"
					>
						{sig.traces_affected.toLocaleString()}
						<span aria-hidden> →</span>
					</Link>
				</TD>

				{/* FIRST / LAST SEEN — both absolute UTC dates in the SAME format, so the
				    pair is directly comparable and never a misleading relative value
				    (the signatures first/last-seen-dates fix). Full timestamp on hover.
				    `mono` because a timestamp is a technical value, and because it makes
				    the two date columns align character-for-character. */}
				<TD mono muted className="whitespace-nowrap text-xs">
					<time dateTime={sig.first_seen} title={sig.first_seen}>
						{absoluteDate(sig.first_seen)}
					</time>
				</TD>
				<TD mono muted className="whitespace-nowrap text-xs">
					<time dateTime={sig.last_seen} title={sig.last_seen}>
						{absoluteDate(sig.last_seen)}
					</time>
				</TD>
			</TR>

			{/* DETAIL — the SAME four pieces of evidence as before (description,
			    detection method, affected-traces link, ledger note), re-laid out.
			    They were four `·` bullets in one column, which gave a one-line fact
			    and a three-line paragraph the same rank. They are now two LABELLED
			    fields side by side, with the affordance and the ledger note on a
			    footer beneath — so the panel has a shape a reader can scan instead of
			    a list to read.
			    NO new field is fetched or computed here — `t.description` and
			    `t.detection` are the AFT-1 taxonomy's own "Description" and
			    "Detection", which is why the labels use those words.
			    `pl-12` hangs the panel under the Signature column rather than under
			    the chevron gutter. */}
			{open && (
				<TDetail colSpan={SIGNATURE_TABLE_COLS} id={detailId} className="pl-12">
					<div className="max-w-4xl space-y-4">
						{hasFields && (
							<div className="grid gap-4 sm:grid-cols-2 sm:gap-6">
								{t?.description && (
									<div>
										<p className="t-metric-label">Description</p>
										<p className="mt-1.5 text-sm text-ink-2">{t.description}</p>
									</div>
								)}
								{t?.detection && (
									<div>
										<p className="t-metric-label">Detection</p>
										<p className="mt-1.5 text-sm text-ink-2">{t.detection}</p>
									</div>
								)}
							</div>
						)}
						{/* The rule SEPARATES the actions from the fields above them, so it
						    only exists when there are fields. An UNMAPPED id has no taxonomy
						    entry, so its panel is the footer alone — and the border was
						    rendering as a hairline hanging off nothing (caught by rendering
						    the open row, not by reading it). */}
						<div
							className={cn(
								"flex flex-wrap items-center gap-x-5 gap-y-2",
								hasFields && "border-t border-line pt-3",
							)}
						>
							<Link
								href={tracesHref}
								onClick={(e) => e.stopPropagation()}
								className="text-sm font-medium text-action-ink hover:underline"
							>
								View {sig.traces_affected.toLocaleString()}{" "}
								{sig.traces_affected === 1
									? "affected trace"
									: "affected traces"}{" "}
								→
							</Link>
							{/* Seal green is the system's ONE rationed provenance mark — it
							    means "tamper-evident record" and nothing else. */}
							<span className="text-xs text-seal-ink">
								Matches recorded in tamper-evident audit ledger — open a trace
								to see its chain status.
							</span>
						</div>
					</div>
				</TDetail>
			)}
		</>
	);
}
