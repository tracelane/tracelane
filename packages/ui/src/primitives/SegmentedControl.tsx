import type { ComponentType, ReactNode } from "react";
import { cn } from "../lib/cn";

/**
 * SegmentedControl — THE one-of-N control. Time ranges, status filters, group-by,
 * page size, spend dimension, plan interval: every place the app asks "which one of
 * these few".
 *
 * ── WHY IT EXISTS ───────────────────────────────────────────────────────────
 * It was hand-rolled TEN times: `RangeControl`, `FilterBar` (×3 — status, range,
 * group), `SessionFilters`, `guardrails/verdicts`, `traces` page-size,
 * `SpendAttribution`, `SupportForm`, `TraceDetailView`, the onboarding language
 * toggle, and `PromotionPanel`'s source-environment picker. Nine of the ten painted
 * the selected option as a SOLID INK PILL (`bg-selected text-selected-on`); the
 * tenth had been refined to a lifted segment, and nobody could see the divergence
 * because no two of them are on the same screen. On `/traces` the effect was five
 * black pills in one filter row — exactly what the P0 brief means by "avoid
 * oversized black pills".
 *
 * IT WAS COUNTED AS NINE FIRST, and the miss is worth recording because of WHERE it
 * hid: the first nine were all found by grepping filter rows and toolbars.
 * `PromotionPanel`'s lives inside a form, in a panel, on `/prompts/[name]` — the
 * same control in different furniture. Its own comment claimed the solid pill
 * "matched every other segment control", which had stopped being true the moment the
 * other nine moved. It also carried no `role`, no accessible name and no
 * `aria-pressed`. An adversarial re-grep for the CONSTRUCTION rather than the
 * CONTEXT found it.
 *
 * ── THE TREATMENT, AND WHY IT IS NOT A BLACK PILL ───────────────────────────
 * A WELL with a LIFTED SEGMENT: the track is `--surface-2` (recessed), the selected
 * segment is `--surface` with a hairline and the card shadow (raised), unselected
 * options are `--ink-2` on nothing.
 *
 * That reads as "this one is chosen" through elevation and tone rather than through
 * maximum contrast, which matters here for a reason beyond taste: a filter row
 * carries five of these, and five solid-ink pills make the CONTROLS the loudest
 * objects on a page whose subject is the data below them. It is also the only
 * treatment that stays legible when two segmented controls sit adjacent — two black
 * pills side by side read as one selection, not two.
 *
 * `--selected` is NOT retired: it remains correct for a single-purpose ACTIVE mark
 * (the primary button) where maximum contrast is the point. It is wrong for
 * one-of-N, where the job is to distinguish among peers.
 *
 * ── HOW IT READS IN DARK, WHICH IS GENUINELY DIFFERENT ──────────────────────
 * Stated because it is not uniform, and because the note used to live in
 * `RangeControl` — the one call site that had already been refined to this
 * treatment — where it described markup that has since moved here.
 * In LIGHT the segment is #ffffff in a #f5f5f4 well: a lift. In DARK `--surface`
 * (#151619) is DARKER than `--surface-2` (#1c1d20), so the same two tokens
 * produce an INSET segment, and `--shadow-card` there is a 20%-black hairline
 * shadow that a dark surface swallows. The segment is still unambiguous — a
 * `--line` edge lighter than both fills, plus primary ink against secondary on
 * its neighbours — but the metaphor flips from lifted to inset. That is a
 * property of the token system (surfaces step toward the light in one theme and
 * away in the other) and NOT something a per-theme override could fix here: the
 * app resolves its theme from a `data-theme` attribute and wires no `dark:`
 * variant, so every class below has to hold unbranched.
 *
 * ── BOTH MODES, BECAUSE THE CALL SITES NEED BOTH ────────────────────────────
 * `onChange` renders `<button>`s (client filters that push a URL param). `hrefFor`
 * renders `<a>`s (server-driven params that must survive with JS off, and that the
 * router can prefetch). Supplying both is a call-site bug and the type forbids it.
 */

export interface SegmentedOption<V extends string = string> {
	value: V;
	label: ReactNode;
	/** Native tooltip — for an abbreviated label like "p95" or "24h". */
	title?: string;
}

type Base<V extends string> = {
	/**
	 * Accessible group name, rendered as the group's `aria-label` (not as an
	 * `sr-only` element — an `aria-label` on the `role="group"` container is what
	 * a screen reader announces when focus enters it). Any VISIBLE label beside
	 * the control stays the caller's.
	 */
	label: string;
	value: V;
	options: ReadonlyArray<SegmentedOption<V>>;
	/** `sm` for dense filter rows (default), `md` where the control stands alone. */
	size?: "sm" | "md";
	/**
	 * Dim the control while a transition is pending. It also sets `aria-busy` on
	 * the group: the dim is colour-only, so on its own it tells a screen-reader
	 * user nothing. One prop, not two, because the dim and the busy state are the
	 * same fact — a caller cannot have one without the other and be honest.
	 */
	pending?: boolean;
	className?: string;
	/** Per-option hover side effect — `router.prefetch` at the link call sites. */
	onOptionHover?: (value: V) => void;
	/**
	 * The component to render each option with in LINK mode. Defaults to a plain
	 * `<a>`.
	 *
	 * WHY THIS PROP EXISTS, because it looks like indirection for its own sake and
	 * is not. `packages/ui` has NO framework dependency — `package.json` lists only
	 * `clsx`, `tailwind-merge` and `cva`, with React as a peer — so this primitive
	 * cannot import `next/link`, and a bare `<a>` is the only thing it can render
	 * on its own.
	 *
	 * BUT A BARE `<a>` IS A FULL DOCUMENT RELOAD. Three call sites
	 * (traces page-size, guardrail verdict filter, gateway spend dimension) used
	 * `next/link` before they moved onto this primitive, and converting them to a
	 * plain anchor silently traded soft client-side navigation for a whole-page
	 * reload on every click. Measured with a `window` marker across a click, not
	 * inferred: the marker survived on a `<Link>` and was lost on the `<a>`. The
	 * URLs were byte-identical, which is exactly why a diff review could not see it.
	 *
	 * So the APP injects its router's link component and keeps soft navigation;
	 * the PACKAGE stays framework-agnostic. Both properties hold at once, which a
	 * hard import of `next/link` would have broken.
	 */
	linkAs?: ComponentType<{
		href: string;
		title?: string;
		className?: string;
		children?: ReactNode;
		onMouseEnter?: () => void;
		"aria-current"?: "true" | undefined;
	}>;
};

export type SegmentedControlProps<V extends string = string> = Base<V> &
	(
		| { onChange: (value: V) => void; hrefFor?: never }
		| { hrefFor: (value: V) => string; onChange?: never }
	);

const SIZE = {
	sm: "px-2.5 py-1 text-xs",
	md: "px-3 py-1.5 text-sm",
} as const;

export function SegmentedControl<V extends string = string>({
	label,
	value,
	options,
	size = "sm",
	pending,
	className,
	onOptionHover,
	linkAs,
	onChange,
	hrefFor,
}: SegmentedControlProps<V>) {
	// `"a"` is the fallback, not the expectation — see `linkAs`.
	const LinkTag = linkAs ?? "a";
	return (
		// `role="group"` + an `aria-label`, NOT `role="radiogroup"` and NOT
		// `role="tablist"`. Both of those promise roving-tabindex arrow-key
		// navigation (and a tablist additionally promises `aria-controls` onto a
		// `role="tabpanel"`), and these are plain buttons/links that each take Tab
		// and control nothing they point at. Claiming the stronger role and not
		// implementing it is worse for a screen-reader user than claiming the weaker
		// one, because it sets an expectation the control does not meet.
		//
		// Two call sites — `SpendAttribution` and `TraceDetailView` — DID claim
		// `role="tablist"`/`role="tab"`/`aria-selected` while implementing neither
		// half of the contract; converting them onto this primitive drops that
		// false promise on purpose, and keeps their `aria-label` verbatim.
		//
		// `useSemanticElements` wants `<fieldset>` instead, which is wrong three ways
		// here: it takes its accessible name from a `<legend>` (a rendered box we
		// would then have to hide, not an `aria-label`); its UA style is
		// `min-inline-size: min-content`, which fights the inline-flex track; and it
		// is defined for grouping FORM controls, while three of the nine call sites
		// render links.
		// biome-ignore lint/a11y/useSemanticElements: `<fieldset>` needs a `<legend>`, carries UA sizing that fights the track, and is for form controls — half these options are links.
		<div
			role="group"
			aria-label={label}
			// Rides on `pending` rather than a second prop. `RangeControl` carried
			// `aria-busy` on its hand-rolled group before it moved onto this
			// primitive, and dropping it would have been a silent a11y regression on
			// the one call site that already had it right.
			aria-busy={pending || undefined}
			className={cn(
				"inline-flex items-center gap-0.5 rounded-[var(--radius-control)] border border-line bg-surface-2 p-0.5",
				pending && "opacity-60",
				"transition-opacity duration-150",
				className,
			)}
		>
			{options.map((o) => {
				const active = o.value === value;
				const cls = cn(
					"rounded-md font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring",
					SIZE[size],
					active
						? // The lifted segment. `border-line` + `--shadow-card` is the same
							// material a Card uses, one size down — so a chosen segment and a
							// card read as the same system.
							"border border-line bg-surface text-ink shadow-[var(--shadow-card)]"
						: // `border-transparent` keeps the inactive options the SAME height as
							// the active one; without it the row shifts 2px when the selection
							// moves, which reads as the control twitching.
							"border border-transparent text-ink-2 hover:text-ink",
				);
				if (hrefFor) {
					return (
						<LinkTag
							key={o.value}
							href={hrefFor(o.value)}
							title={o.title}
							aria-current={active ? "true" : undefined}
							onMouseEnter={
								onOptionHover ? () => onOptionHover(o.value) : undefined
							}
							className={cls}
						>
							{o.label}
						</LinkTag>
					);
				}
				return (
					<button
						key={o.value}
						type="button"
						title={o.title}
						aria-pressed={active}
						onClick={() => onChange?.(o.value)}
						onMouseEnter={
							onOptionHover ? () => onOptionHover(o.value) : undefined
						}
						className={cls}
					>
						{o.label}
					</button>
				);
			})}
		</div>
	);
}
