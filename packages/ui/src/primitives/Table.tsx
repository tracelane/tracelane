import type {
	HTMLAttributes,
	ReactNode,
	TdHTMLAttributes,
	ThHTMLAttributes,
} from "react";
import { cn } from "../lib/cn";

/**
 * THE Tracelane table system. One header height, one row height, one border
 * treatment, one hover, one alignment rule.
 *
 * ── WHY IT EXISTS ───────────────────────────────────────────────────────────
 * The app hand-rolled 21 tables. Measured across them on 2026-08-22: SEVEN distinct
 * `<thead>` treatments (`border-b border-line` · `border-y … bg-canvas-sunken` ·
 * `bg-surface` · `bg-surface-2` · three more), EIGHT `<th>` class strings, and THREE
 * different row hovers (`surface-2`, `surface-hover`, `surface-3`). No two tables in
 * the product agreed on what a table looks like, and nobody could see it because no
 * two of them are on the same screen — the same blindness that let ten segmented
 * controls diverge.
 *
 * THIS HAS CONVERTED 7 OF THE 21, NOT ALL OF THEM — corrected here after the P1
 * verifier caught the original wording claiming otherwise. The P1 pass covered
 * `/gateway`, `/guardrails`, `/guardrails/verdicts`, `/slo` and `/signatures`; 14
 * files still hand-roll a table, **including `apps/web/app/dashboard/page.tsx`
 * (3 of them)** — the page that is the design reference for everything else. That is
 * the next conversion, and stating the real number is the only way the gap stays
 * visible: a primitive whose docstring claims a completed migration is how the
 * remaining call sites become invisible.
 *
 * ── THE ALIGNMENT RULE, WHICH IS THE WHOLE POINT OF A DATA TABLE ────────────
 * Text left. Numbers right, tabular, monospace. A column of figures that does not
 * share a decimal position cannot be compared by eye, which is the only reason to
 * put numbers in a column at all. `numeric` does all three at once so a call site
 * cannot get one of them and forget the others — which is exactly how the eight
 * `<th>` variants happened.
 *
 * `mono` is the separate case: a technical IDENTIFIER (trace id, signature id, model
 * name, hash) that belongs in a LEFT column but must still be monospace. Splitting it
 * from `numeric` keeps "is it a number" and "is it an identifier" as different
 * questions, because they have different alignments.
 *
 * ── WHAT IT DELIBERATELY DOES NOT DO ────────────────────────────────────────
 * No sorting, no pagination, no virtualisation, no column config. Those are behaviour,
 * and every existing table already implements whatever it needs at the call site. This
 * is a VISUAL system: adding behaviour here would make it a second, competing table
 * abstraction rather than one shared skin.
 *
 * No zebra striping and no decorative background. A tinted row is a colour that means
 * nothing, and this product's rule is that colour is data.
 */

/**
 * The scroll container + the table element. ALWAYS use this rather than a bare
 * `<table>`: the `overflow-x-auto` wrapper is what keeps a wide table from pushing the
 * whole page sideways on a phone, and a page that scrolls horizontally is the single
 * most common way a responsive layout fails.
 */
export function Table({
	className,
	children,
	...props
}: HTMLAttributes<HTMLTableElement> & { children: ReactNode }) {
	return (
		<div className="w-full overflow-x-auto">
			<table
				className={cn("w-full border-collapse text-sm", className)}
				{...props}
			>
				{children}
			</table>
		</div>
	);
}

/**
 * The header band. `--canvas-sunken` is one step UNDER the card it sits on, so the
 * header reads as a recessed rail rather than as a first row — the same sunken
 * relationship the sub-nav strips use. Bordered top and bottom so it holds its edge
 * whether or not the table starts at the top of its card.
 */
export function THead({
	className,
	children,
	...props
}: HTMLAttributes<HTMLTableSectionElement> & { children: ReactNode }) {
	return (
		<thead
			className={cn("border-y border-line bg-canvas-sunken", className)}
			{...props}
		>
			{children}
		</thead>
	);
}

export function TBody({
	className,
	children,
	...props
}: HTMLAttributes<HTMLTableSectionElement> & { children: ReactNode }) {
	return (
		<tbody className={cn("divide-y divide-line", className)} {...props}>
			{children}
		</tbody>
	);
}

export interface TRProps extends HTMLAttributes<HTMLTableRowElement> {
	/** Row responds to the pointer — set it when the row is clickable or expandable. */
	interactive?: boolean;
	/** The row is currently expanded; pairs with a detail row beneath it. */
	expanded?: boolean;
}

export function TR({ className, interactive, expanded, ...props }: TRProps) {
	return (
		<tr
			className={cn(
				"transition-colors",
				// ONE hover token. The tree had three (`surface-2`, `surface-hover`,
				// `surface-3`); `--surface-hover` is the role that exists for exactly
				// this — a step off the CARD colour, in the right direction in both
				// themes (lighter in dark, darker in light).
				interactive && "cursor-pointer hover:bg-surface-hover",
				// An expanded row keeps the hover tone permanently, so the open row and
				// its detail panel read as one object rather than two stacked rows.
				expanded && "bg-surface-hover",
				className,
			)}
			{...props}
		/>
	);
}

export interface THProps extends ThHTMLAttributes<HTMLTableCellElement> {
	/** Right-aligned. Use for every column whose cells are `numeric`. */
	numeric?: boolean;
}

/**
 * A header cell. Type comes from `.t-metric-label` (11px / 600 / 0.06em / `--ink-2`),
 * the same role the metric tiles label with — so a column header and a KPI label are
 * the same object in the type system rather than two near-copies.
 */
export function TH({ className, numeric, ...props }: THProps) {
	return (
		<th
			scope="col"
			className={cn(
				"t-metric-label px-4 py-2.5 align-middle",
				numeric ? "text-right" : "text-left",
				className,
			)}
			{...props}
		/>
	);
}

export interface TDProps extends TdHTMLAttributes<HTMLTableCellElement> {
	/** A number: right-aligned, tabular, monospace. All three, always, together. */
	numeric?: boolean;
	/** A technical identifier in a LEFT column: monospace, not right-aligned. */
	mono?: boolean;
	/** De-emphasise to secondary ink — a supporting value, not the row's subject. */
	muted?: boolean;
}

export function TD({ className, numeric, mono, muted, ...props }: TDProps) {
	return (
		<td
			className={cn(
				// `py-3` against the header's `py-2.5`: rows are the thing being read,
				// so they get the taller box. It is also the minimum that keeps a
				// two-line cell (a wrapped model name) from touching its neighbours.
				"px-4 py-3 align-middle",
				numeric && "text-right font-mono tabular-nums",
				mono && "font-mono",
				muted ? "text-ink-2" : "text-ink",
				className,
			)}
			{...props}
		/>
	);
}

/**
 * The full-width panel under an expanded row. It spans every column and sits on the
 * well, so an open row reads as one object with a body rather than as a row followed
 * by an unrelated wide row.
 *
 * `colSpan` is REQUIRED and deliberately not defaulted: a wrong span silently breaks
 * the column grid for the whole table, and there is no correct guess a component can
 * make about a caller's column count.
 */
export function TDetail({
	colSpan,
	className,
	children,
	...props
}: TdHTMLAttributes<HTMLTableCellElement> & {
	colSpan: number;
	children: ReactNode;
}) {
	return (
		<tr className="bg-surface-2">
			<td colSpan={colSpan} className={cn("px-4 py-4", className)} {...props}>
				{children}
			</td>
		</tr>
	);
}
