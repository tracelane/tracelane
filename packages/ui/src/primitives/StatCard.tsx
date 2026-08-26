import type { ReactNode } from "react";
import { SparkBars } from "../charts/SparkBars";
import { cn } from "../lib/cn";
import { MetricIcon, type MetricIconName } from "./MetricIcon";

/**
 * StatCard — the ONE premium metric tile shared across every dashboard surface
 * (Dashboard / SLO / Gateway / Guardrails / Signatures). A single component so
 * the metric row reads as one system, not five per-page reimplementations.
 *
 * ── LOOK, REWRITTEN FOR THE P0 BRIEF (2026-08-22) ───────────────────────────
 *
 * THE NUMBER IS THE TILE. Three sizes of hierarchy and nothing else: an 11px
 * uppercase micro-label (`.t-metric-label`), a 28px tabular value (`.t-metric`),
 * and an optional 11px sub-line. P0.6 asks for the value to dominate, and it now
 * does by ~2.5× rather than by ~1.6×.
 *
 * THE SURFACE IS `.stat-tile` FOR ALL THREE VARIANTS — radius, hairline,
 * background and the ~2% contact shadow all live in tokens.css, so a tile and a
 * `<Card>` beside it are the same material. `inverse` and `action` used to
 * hardcode `rounded-lg` (8px, the CONTROL radius) while the default variant took
 * `--radius-card` (18px) from `.stat-tile`: three tiles in one row at two
 * different radii, which is exactly the "wireframe of rounded rectangles" tell
 * the brief opens by naming. They now share the class and override only the fill.
 *
 * THE DELTA IS NOT A PILL. It was a filled `rounded-full bg-surface-2` chip; P0.6
 * bans coloured/oversized pills as the main KPI treatment. It is now a borderless
 * inline `↑/↓/— value` in mono, so the tile carries ONE enclosed shape (itself)
 * instead of two. The value stays graphite/white and the DELTA carries the
 * semantic colour — the change is the thing with a direction, not the reading.
 *
 * COLOUR IS NEVER ALONE: the delta renders a direction glyph AND the caller's
 * signed string, so a monochrome or colour-blind reading loses nothing.
 *
 * CORRECTED HERE, because the previous docstring described a surface that no
 * longer exists: it said "a hairline border plus the near-invisible G1 container
 * tint". That tint (`linear-gradient(160deg, #fcfdfe …)`) was DELETED from
 * `.stat-tile` in this pass — #fcfdfe has B > R, so every metric tile in the app
 * was washing a faint blue over its top-left corner, which is the "pale-blue
 * cast" P0.1 exists to remove. Separation is now tone + hairline + a 2% shadow.
 *
 * The `interactive` variant deepens its border and surface on hover and lands one
 * step deeper on `:active`. It does NOT move: the 1px lift was removed on
 * 2026-08-16 because on a twelve-tile grid a lift reads as the page twitching
 * rather than as an affordance.
 */

export type StatTone = "default" | "ok" | "warn" | "danger";

/**
 * Card surface (app design system):
 *  - `default`  the standard tile — white sheet, hairline, 2% contact shadow.
 *  - `inverse`  the deliberate dark card (`--surface-inverse`) — the SLO
 *               error-budget / burn-rate hero. Its value paints in `--ink-inverse`.
 *  - `action`   the quiet well tile (`--action-soft`, which is the ink family's
 *               soft step, NOT a tint) — the block-rate / budget-remaining card.
 *               It was described as "a lava-soft tinted card"; lava is deleted and
 *               the token now resolves to the same neutral as `--surface-2`.
 */
export type StatVariant = "default" | "inverse" | "action";

export interface StatCardProps {
	/** Micro uppercase label — rendered with `.t-metric-label` (11/600/0.08em). */
	label: ReactNode;
	/** The metric — rendered large (`.t-metric`), tabular-nums, tone-colored. */
	value: ReactNode;
	/** Tone for the value (color + meaning; never color alone — pair with copy). Applies to the `default` variant. */
	tone?: StatTone;
	/** Card surface — see StatVariant. */
	variant?: StatVariant;
	/** Secondary line under the value (context / denominator / "1.0× = on pace"). */
	sub?: ReactNode;
	/** Native tooltip on the label (jargon → plain language) + a `?` affordance. */
	hint?: string;
	/** Optional monochrome metric-icon chip on the label row — the SAME shared
	 *  `MetricIcon` as the dashboard, so every surface reads as one system. */
	icon?: MetricIconName;
	/**
	 * Hover/press affordance + pointer cursor — set when the tile is wrapped in a
	 * link or button (default variant only). Border + surface change; no lift
	 * (see the header — this said "Lift-on-hover" until 2026-08-17, and the lift
	 * had been gone since 2026-08-16).
	 */
	interactive?: boolean;
	/**
	 * Period-over-period change. Rendered as a BORDERLESS inline delta — a
	 * direction glyph plus the caller's string, in mono, carrying the semantic
	 * colour — never colour alone, and never a filled pill (P0.6).
	 *
	 * `up` is not automatically good (a rising error rate is not a win), so the
	 * CALLER states the tone. An untoned delta is `--ink-3`: a change we are not
	 * asserting anything about must not borrow green or red.
	 */
	delta?: { value: string; direction: "up" | "down" | "flat"; tone?: StatTone };
	/**
	 * Optional micro bar series behind the value — a shape for the trend, at a glance,
	 * without a second chart. BARS, not a sparkline: these are buckets (see BarChart).
	 * Values are normalised internally; pass raw numbers.
	 */
	spark?: readonly number[];
	className?: string;
}

/** Tone → VALUE colour. `default` is primary ink: the reading is the point. */
const TONE: Record<StatTone, string> = {
	default: "text-ink",
	ok: "text-ok-ink",
	warn: "text-warn-ink",
	danger: "text-danger-ink",
};

/**
 * Tone → DELTA colour. A separate map from `TONE` on purpose: an untoned VALUE is
 * `--ink` (it is the headline), an untoned DELTA is `--ink-3` (it is an aside).
 * Collapsing them would put a 12px mono delta at full ink weight beside a 28px
 * number and flatten the very hierarchy P0.6 is asking for.
 */
const DELTA_TONE: Record<StatTone, string> = {
	default: "text-ink-3",
	ok: "text-ok-ink",
	warn: "text-warn-ink",
	danger: "text-danger-ink",
};

/** Direction glyph. Rendered `aria-hidden` — the signed string beside it is what
 *  a screen reader needs, and "▲ +8%" read aloud twice is noise. */
const DELTA_GLYPH: Record<
	NonNullable<StatCardProps["delta"]>["direction"],
	string
> = { up: "▲", down: "▼", flat: "—" };

export function StatCard({
	label,
	value,
	tone = "default",
	variant = "default",
	sub,
	hint,
	icon,
	interactive,
	delta,
	spark,
	className,
}: StatCardProps) {
	const isDefault = variant === "default";
	// ONE surface class for every variant — see the header. `.stat-tile` supplies
	// `--radius-card`, the hairline, the fill and the contact shadow; a variant
	// overrides ONLY the fill, because a utility (@layer utilities) beats the
	// component-layer rule. p-5 is the P0.15 card-padding band (20–24px) read at
	// the adaptive root: 1.25rem lands at ~18px at 1440 and 20px at 1920.
	const card =
		variant === "inverse"
			? // The hairline is INHERITED from `.stat-tile`, not suppressed. It used to
				// be `border-transparent`, and tokens.css says why that was wrong: in DARK
				// theme `--surface-inverse` IS the page ground (#0d0e10), so a
				// transparent-bordered inverse tile has no edge of any kind and dissolves
				// into the canvas behind it. In light theme `--line` on a near-black fill
				// is a 1px step the ground already almost matches, so it costs nothing.
				"stat-tile bg-surface-inverse p-5"
			: variant === "action"
				? "stat-tile border-action-line bg-action-soft p-5"
				: "stat-tile p-5";
	// `.t-metric-label` already paints `--ink-2`, so `default` and `action` pass
	// NOTHING here and inherit the one definition of what a metric label is. Only
	// the dark card needs its own tone.
	const labelCls =
		variant === "inverse" ? "text-ink-inverse opacity-70" : undefined;
	const valueCls =
		variant === "inverse"
			? // INK ON INK. This was `text-action`, which was correct while --action was
				// lava. The ink remap made --action monochrome, and --surface-inverse is
				// ALSO ink — so in LIGHT theme the value rendered #0d0d0d on #0d0d0d: a
				// 1:1 contrast ratio, completely invisible. Dark theme was fine (light
				// action on dark card), which is why it survived review and shipped. The
				// value on an inverse surface must use the token that EXISTS to be
				// legible on it.
				"text-ink-inverse"
			: variant === "action"
				? "text-ink"
				: TONE[tone];
	const subCls =
		variant === "inverse" ? "text-ink-inverse opacity-60" : "text-ink-3";

	return (
		// `flex h-full flex-col` is what makes a ROW of tiles align: the label row sits
		// at the top, the value block is pushed to a common baseline by `mt-auto`, and a
		// tile without a `sub` no longer floats its value halfway up while its neighbour
		// with a `sub` sits low. Grid `items-stretch` (StatGrid) supplies the equal height.
		<div
			className={cn(
				card,
				"flex h-full flex-col",
				isDefault && interactive && "stat-tile--interactive",
				className,
			)}
		>
			<div className="mb-2 flex items-center gap-2">
				{icon && (
					<MetricIcon name={icon} size={18} onInverse={variant === "inverse"} />
				)}
				<p className={cn("t-metric-label flex items-center gap-1", labelCls)}>
					{label}
					{/* Real tooltip, not a native `title`: `title` never fires on touch
				    devices and lags ~1s on desktop, so the `?` looked dead. This shows
				    on hover, keyboard focus AND tap (focus-within). */}
					{hint && (
						<span className="group relative inline-flex">
							<button
								type="button"
								aria-label={hint}
								// The `variant === "inverse"` branch is the per-site focus override
								// tokens.css's `--focus-ring` note says a focusable control inside a
								// `--surface-inverse` card "would still need" — while asserting "there are
								// none". This is one of them (2026-08-22 contrast audit). `--focus-ring` is
								// `--ink`, so in LIGHT theme the ring paints #171717 on a #151619 tile =
								// 1.01:1, and `outline-offset: 2px` cannot rescue it here because the ring
								// lands on the TILE, not on the canvas behind it. `--ink-inverse` is the
								// token defined to be legible on that surface: 16.60:1 / 17.71:1.
								// Latent today — no call site passes `variant="inverse"` WITH a `hint` —
								// which is precisely the state the ink-on-ink defects in this file shipped
								// from. A colour override on the base ring; not `outline-none`, not a
								// second ring mechanism.
								className={cn(
									"grid h-4 w-4 cursor-help place-items-center rounded-full border border-line-2 text-2xs leading-none text-ink-3 transition-colors hover:border-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring",
									variant === "inverse" && "focus-visible:outline-ink-inverse",
								)}
							>
								?
							</button>
							{/*
							 * 2026-08-17 — three fixes to a tooltip that was correct in
							 * mechanism and wrong in feel.
							 *
							 * ORIGIN-AWARE SCALE. It crossfaded opacity only, so it
							 * appeared in place with no sense of coming FROM the `?`.
							 * `scale-95` + `origin-top` grows it downward out of the
							 * trigger it is anchored under. Not `scale-0` — nothing in the
							 * real world appears from nothing.
							 *
							 * A SHOW DELAY, AND ONLY ON SHOW. It opened the instant the
							 * pointer touched the `?`, so dragging the mouse across a
							 * twelve-tile metric row strobed tooltips the user never asked
							 * for. `group-hover:delay-300` delays the ENTER; the base
							 * `delay-0` means the exit is still immediate — slow where the
							 * user is deciding, fast where the system responds.
							 *
							 * NOT ANNOUNCED TWICE. `role="tooltip"` with no
							 * `aria-describedby` pointing at it was doing no a11y work, but
							 * its text was still in the accessibility tree — and the button
							 * already carries the same string as `aria-label`, so a screen
							 * reader read the hint, then read it again. The visual layer is
							 * now `aria-hidden`; the `aria-label` is the accessible name.
							 *
							 * ELEVATION IS A TOKEN NOW (2026-08-22). It carried Tailwind's
							 * stock `shadow-lg` — a 10px/15px drop that is heavier than
							 * anything else in the system and is the one thing the brief
							 * names as making a data surface feel cheap. `--shadow-overlay`
							 * is the system's one overlay elevation, the same value the
							 * `.tl-tooltip` primitive spends.
							 *
							 * Duration 125ms is the small-popover band (125–200ms) and the
							 * easing is inherited: `--default-transition-timing-function`
							 * is now the system ease-out (tokens.css). The property list names `scale`,
							 * not `transform`: Tailwind v4 compiles `scale-95` to the individual
							 * `scale` property, so a list saying `transform` would have transitioned
							 * the opacity and SNAPPED the scale.
							 */}
							<span
								aria-hidden="true"
								className="pointer-events-none absolute left-1/2 top-full z-30 mt-1.5 w-56 origin-top -translate-x-1/2 scale-95 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-2xs font-normal normal-case leading-snug tracking-normal text-ink-2 opacity-0 shadow-[var(--shadow-overlay)] transition-[opacity,scale] duration-125 delay-0 group-hover:scale-100 group-hover:opacity-100 group-hover:delay-300 group-focus-within:scale-100 group-focus-within:opacity-100"
							>
								{hint}
							</span>
						</span>
					)}
				</p>
			</div>
			<div className="mt-auto">
				<div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
					<p className={cn("t-metric", valueCls)}>{value}</p>
					{/* Borderless inline delta (P0.6) — no fill, no border, no radius.
					    The glyph is the non-colour channel; the caller's signed string is
					    the accessible one. `font-mono` because a percentage is a technical
					    value, and `tabular-nums` so a ticking delta cannot jitter the row
					    it sits in. */}
					{delta && (
						<span
							className={cn(
								"inline-flex items-center gap-1 font-mono text-xs leading-none",
								// The semantic `-ink` tones are tuned against a LIGHT card and
								// do not clear AA on `--surface-inverse`, so the dark tile
								// spends the inverse ink and lets the glyph carry direction.
								variant === "inverse"
									? "text-ink-inverse opacity-70"
									: DELTA_TONE[delta.tone ?? "default"],
							)}
							style={{ fontVariantNumeric: "tabular-nums" }}
						>
							<span aria-hidden="true">{DELTA_GLYPH[delta.direction]}</span>
							{delta.value}
						</span>
					)}
				</div>
				{/* DSH-08: the shared `SparkBars` — this was a private `Spark` at the
				    bottom of this file until the dashboard's KPI strip needed the same
				    shape. It guards `length < 2` itself, so the check that used to be
				    here is gone rather than duplicated. */}
				{/* `variant === "inverse"`, NOT `!isDefault` (2026-08-22 contrast audit).
				    `inverse` makes SparkBars paint `fill-ink-inverse opacity-45`, and
				    `--ink-inverse` is #f5f5f5 in BOTH themes — correct on the near-black
				    inverse tile (4.22:1 / 4.24:1), wrong on the ACTION tile, whose fill is
				    `--action-soft` = #f5f5f4 in light. `!isDefault` swept the action tile in
				    with the inverse one, so an action tile given a `spark` would have
				    composited its bars to #f5f5f4 on #f5f5f4 — 1.00:1, the same ink-on-ink
				    class this file's `valueCls` note records shipping once. Latent rather
				    than live (no action-variant call site passes `spark` today), which is
				    exactly how the first one shipped.

				    THE COMMENT LIVED INSIDE `{spark && ( … )}` and broke the parse: the
				    right-hand side of `&&` is ONE expression, so a JSX comment beside the
				    element is a syntax error, not a comment. It is hoisted here. */}
				{spark && (
					<SparkBars
						values={spark}
						inverse={variant === "inverse"}
						className="mt-2"
					/>
				)}
				{/* Reserved line: keeps every tile in a row the same height even when
				    only some have a sub-line, without forcing callers to pass an empty
				    string. An `&nbsp;` would be a lie to a screen reader; this is not
				    rendered at all, it just holds the box.

				    ITS HEIGHT IS PINNED TO THE 2xs LINE BOX AND MUST MOVE WITH IT. The
				    spacer was `h-[1.1em]`, an em of its OWN font-size — 12.1px against a
				    real sub-line of 14.85px, so it was never actually reserving the right
				    height and a tile with no `sub` sat ~2.75px shorter than its neighbour.
				    It is now 0.9375rem, the literal value of `--text-2xs--line-height`
				    (tokens.css). Change one and change the other. */}
				{sub ? (
					<p className={cn("mt-1 text-2xs", subCls)}>{sub}</p>
				) : (
					<p aria-hidden="true" className="mt-1 h-[0.9375rem] text-2xs" />
				)}
			</div>
		</div>
	);
}
