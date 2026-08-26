import { type VariantProps, cva } from "class-variance-authority";
import { type ButtonHTMLAttributes, forwardRef } from "react";
import { cn } from "../lib/cn";

/*
 * PRESS FEEDBACK (2026-08-17). Two defects, one of them inverted.
 *
 * 1. `primary` read `hover:opacity-90 active:opacity-95`. Both apply while the
 *    button is held, and Tailwind orders `active` after `hover`, so the sequence
 *    a user actually saw was rest 100% -> hover 90% -> PRESS 95%: the press moved
 *    the button BACK TOWARD its resting state. Pressing made it look less
 *    pressed. Now monotonic: 100 -> 90 -> 80.
 * 2. `secondary` / `ghost` / `danger` had no `:active` state at all — three of
 *    four variants gave zero feedback that the interface had heard the click.
 *    Each now lands one surface step deeper: rest -> `--surface-2` on hover ->
 *    `--surface-3` on press.
 *
 *    CORRECTED 2026-08-22: this line claimed `active:bg-surface-3` was "the SAME
 *    step `.stat-tile--interactive:active` uses". It is not, and has not been
 *    since the tile picked up `--surface-hover` — the tile now runs
 *    surface-hover -> surface-2, one step LIGHTER than a button at each stage.
 *    That difference is deliberate, not drift: a tile is a large passive surface
 *    where a visible wash reads as the page flinching, and a button is a small
 *    element under the user's finger where the feedback has to be unmistakable.
 *    A comment asserting they are identical is the kind of thing that gets cited
 *    in review as though it held (CLAUDE.md §17).
 *
 * `active:scale-[0.98]` is the shared part (emilkowalski/skills: subtle,
 * 0.95–0.98, 100–160ms — it inherits `--dur-fast` = 140ms). Deliberately NOT
 * gated behind `motion-reduce:`: this is direct-manipulation feedback on the
 * element under the user's own finger, which is not the unexpected-movement
 * class `prefers-reduced-motion` exists to suppress. `disabled:pointer-events-none`
 * already makes `:active` unreachable when disabled.
 *
 * `transition-colors` could not carry it — that utility's property list is
 * colours only, so a `scale` on `:active` would have snapped. The explicit
 * property list is the alternative to `transition: all`, which is banned.
 *
 * AND IT MUST NAME `scale`, NOT `transform`. Tailwind v4 compiles
 * `active:scale-[0.98]` to the individual CSS property `scale: 0.98`, not to a
 * `transform` function — verified by compiling this stylesheet, where
 * `transition-transform` itself expands to
 * `transition-property: transform, translate, scale, rotate` for exactly this
 * reason. A list saying only `transform` transitions nothing and the press would
 * have snapped anyway, silently, while looking correct in the diff.
 *
 * RADIUS: `rounded-md` (6px), and it stays there. tokens.css now splits the
 * radius in two — `--radius-card` 18px for cards/tiles/panels, `--radius-control`
 * 8px for buttons/inputs/chips — and a button at the CARD radius is what makes a
 * surface read as a wireframe of rounded rectangles rather than as a sheet with
 * controls on it. 6px is the small end of the control band and keeps a button
 * visibly tighter than the 18px card behind it.
 */
const button = cva(
	"inline-flex items-center justify-center gap-2 rounded-md font-medium whitespace-nowrap transition-[color,background-color,border-color,opacity,scale] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50",
	{
		variants: {
			variant: {
				/*
				 * SOLID INK PRIMARY — and the token is `--selected`, NOT
				 * `--surface-inverse`. THE BUG THIS FIXES (P0.4/P0.12, 2026-08-22):
				 * `bg-surface-inverse text-ink-inverse` is correct in light theme
				 * (#151619 fill, near-white label) and BROKEN in dark, because in dark
				 * `--surface-inverse` is #0d0e10 — the PAGE GROUND. The primary call to
				 * action was a near-invisible dark rectangle sitting on a #151619 card,
				 * separated from it by 2% of luminance, with the highest-intent action
				 * in the product inside it.
				 *
				 * `--selected` is the pair that was built to survive the flip: #171717
				 * with a #ffffff label in light (17.93:1), #f5f5f5 with a #0d0e10 label
				 * in dark (17.71:1). Solid ink in light, a light pill in dark — the same
				 * "highest-intent, no hue" reading in both themes, which is what P0.18
				 * requires of every semantic level. Verified against the token values in
				 * packages/ui/src/styles/tokens.css before the swap, not assumed.
				 *
				 * There is no accent colour in this system, so intent is expressed by
				 * WEIGHT: solid ink for primary, a hairline for secondary, nothing for
				 * ghost. `bg-action` remains the equivalent solid-fill token; `selected`
				 * is preferred here because it is the pair whose label token is defined
				 * for both directions.
				 */
				primary:
					"bg-selected text-selected-on hover:opacity-90 active:opacity-80",
				secondary:
					"border border-line bg-surface text-ink hover:bg-surface-2 active:bg-surface-3",
				ghost:
					"text-ink-2 hover:bg-surface-2 hover:text-ink active:bg-surface-3",
				danger:
					"bg-danger text-danger-on hover:bg-danger/90 active:bg-danger/80",
			},
			size: {
				sm: "h-8 px-3 text-xs",
				md: "h-9 px-4 text-sm",
				lg: "h-10 px-5 text-sm",
			},
		},
		defaultVariants: { variant: "secondary", size: "md" },
	},
);

export interface ButtonProps
	extends ButtonHTMLAttributes<HTMLButtonElement>,
		VariantProps<typeof button> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
	({ className, variant, size, ...props }, ref) => (
		<button
			ref={ref}
			className={cn(button({ variant, size }), className)}
			{...props}
		/>
	),
);
Button.displayName = "Button";
