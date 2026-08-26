import { type VariantProps, cva } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

/*
 * Badge — the small status/count chip.
 *
 * QUIETER AND MORE PRECISE (P0.12, 2026-08-22). Two changes, both about weight
 * rather than colour:
 *
 *  · `font-semibold` -> `font-medium`. At 11px, semibold on a tinted fill is
 *    close to the visual weight of a 13px card title, so a row of six chips
 *    competed with the headings above them. The chip is an annotation; it should
 *    read at the bottom of the hierarchy, not the middle.
 *  · `rounded-md` (6px) is KEPT and is now a deliberate statement rather than an
 *    inherited default: `--radius-control` is 8px, cards are 18px, and a badge is
 *    the smallest control in the system — the small end of the control band. A
 *    `rounded-full` pill here is what P0.6 bans as "decorative coloured badges".
 *
 * THE TONE MAP IS UNCHANGED AND EVERY TONE IS ALREADY CORRECT: each is the
 * `-soft` FILL with the matching `-ink` TEXT, which is the pairing tokens.css
 * defines as AA-cleared in both themes. Audited line by line on 2026-08-22 —
 * `bg-ok-soft/text-ok-ink`, `bg-warn-soft/text-warn-ink`,
 * `bg-danger-soft/text-danger-ink`, `bg-seal-soft/text-seal-ink`. Nothing here
 * uses a raw fill token (`bg-ok`) as a background under dark text, which is the
 * mistake this pairing exists to prevent.
 *
 * `info` AND `neutral` NOW SEPARATE ON INK, NOT ON FILL — measured, because they sit
 * side by side. `/signatures` renders `info` for an id that maps to the AFT-1 taxonomy
 * and `neutral` for one that does not, in adjacent rows of the same column. Their
 * FILLS are four values apart (`--info-soft` #f1f1f0 vs `--surface-2` #f5f5f4), which
 * is invisible — but their TEXT is not: #202124 at 15.7:1 against #6b6b6b at 4.89:1,
 * a 3x step in darkness. That is the monochrome way to make the distinction and it
 * works; what does NOT work is reading the fills and concluding the tones are
 * interchangeable. If a future call site needs the two to differ at a glance without
 * reading the label, the answer is a deeper WELL for `info`, not a hue.
 *
 * `info` is NOT blue any more. `--info` was #1d5bd0 and now resolves to the chart
 * neutrals, so an `info` badge is a grey chip — the same retarget tokens.css
 * records, visible here because this is one of the few surfaces that spends it.
 * `action` is likewise neutral: `--action-soft` is `--surface-2` and
 * `--action-ink` is `--ink`, so the "active / function" chip reads as an INK chip
 * with no hue at all. Under "colour is data" that is the point — an active state
 * is not a measurement, so it gets no colour.
 *
 * Status tones still pair with an icon or a word at the call site — never colour
 * alone.
 */
const badge = cva(
	// `whitespace-nowrap`, from the render: in the dashboard's failure-signature
	// table the ACTION column is the narrowest, and `flag-only` wrapped to
	// "flag-" / "only" — a two-line chip in a one-line row, which pushed the row
	// taller than its neighbours and read as a layout fault. A status chip is a
	// single token by definition; if it does not fit, the COLUMN is wrong, and a
	// chip that refuses to wrap is what makes that visible instead of hiding it.
	"inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-2xs font-medium tabular-nums",
	{
		variants: {
			tone: {
				neutral: "bg-surface-2 text-ink-2",
				ok: "bg-ok-soft text-ok-ink",
				danger: "bg-danger-soft text-danger-ink",
				warn: "bg-warn-soft text-warn-ink",
				info: "bg-info-soft text-info-ink", // chart-neutral, NOT blue (see above)
				seal: "bg-seal-soft text-seal-ink", // provenance chip — the one rationed green
				action: "bg-action-soft text-action-ink", // neutral ink chip: active / function
			},
		},
		defaultVariants: { tone: "neutral" },
	},
);

export interface BadgeProps
	extends HTMLAttributes<HTMLSpanElement>,
		VariantProps<typeof badge> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
	return <span className={cn(badge({ tone }), className)} {...props} />;
}
