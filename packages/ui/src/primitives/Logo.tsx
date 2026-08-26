import { cn } from "../lib/cn";

export interface LogoProps {
	/** pixel height of the mark (and the lockup). Default 26 — the marketing-site size. */
	height?: number;
	/** render the full lockup (Chisel mark + "tracelane" wordmark); else just the mark. */
	withWordmark?: boolean;
	className?: string;
}

/**
 * Tracelane brand lockup — the geometric **T monogram** + "tracelane" wordmark
 * (ADR-074 §8), rendered IDENTICALLY to the marketing site header.
 *
 * THE MARK IS GENERATED GEOMETRY, NOT A DRAWING. The five paths below are the exact
 * polygons in `scripts/brand/build-brand-assets.py` — 100x100 grid, stroke 12, counter
 * gap 10, every diagonal at 45 degrees. Every favicon, app icon and lockup in `brand/`
 * comes from those same numbers, so the header mark and the browser-tab icon cannot
 * drift. If the mark changes, change it THERE and copy the paths here.
 *
 * The Chisel bracket-recorder it replaced (`viewBox 0 0 76 76`, two brackets, a tick
 * and a bullseye) is dead — ADR-074 §8: "do not resurrect it from any spec". It
 * survived in FIVE places after the brand assets were rebuilt, because generating the
 * files is not the same as wiring them in; `scripts/ci/check-retired-logo.py` now
 * blocks its return.
 *
 * ONE source of truth so the app header and the site header can't drift (the
 * previous app logo was a separate PNG raster, which is why it looked
 * undersized/underweight). Monochrome per the logo lock via `currentColor` →
 * `--logo-ink`, which tracks `--ink` in both themes and is never coloured.
 * The wordmark font comes from `--font-display`.
 *
 * TWO STALE FACTS CORRECTED 2026-08-22 (CLAUDE.md §17 — the code wins). This
 * block said `--logo-ink` was "#0c0d0f on light … never lava" and that the app
 * "wires Source Serif 4" behind `--font-display`. Neither is true: tokens.css
 * holds `--logo-ink: #171717` (light) / `#f5f5f5` (dark), lava is deleted from
 * the system, and `apps/web/app/globals.css:44` points `--font-display` at Geist
 * — the lockup is sans, and has been since the serif was confined to marketing.
 * The GEOMETRY below is unchanged and remains the generated brand paths.
 */
export function Logo({
	height = 26,
	withWordmark = false,
	className,
}: LogoProps) {
	// Proportions locked to the site lockup: mark 26px ↔ wordmark 18px (size-lg)
	// ↔ gap 10px (gap-2.5). Scaled off `height` so any size stays true to spec.
	const wordmarkPx = Math.round(height * (18 / 26));
	const gapPx = Math.round(height * (10 / 26));
	return (
		<span
			role="img"
			aria-label="Tracelane"
			className={cn("inline-flex items-center align-middle", className)}
			style={{ color: "var(--logo-ink)", gap: withWordmark ? gapPx : 0 }}
		>
			<svg
				viewBox="0 0 100 100"
				width={height}
				height={height}
				aria-hidden="true"
				style={{ display: "block", flexShrink: 0 }}
			>
				<path d="M 2,2 L 96,2 L 84,14 L 2,14 Z" fill="currentColor" />
				<path
					d="M 2,14 L 14,14 L 14,28 L 44,28 L 44,40 L 12,40 L 2,30 Z"
					fill="currentColor"
				/>
				<path d="M 32,40 L 44,40 L 44,86 L 32,98 Z" fill="currentColor" />
				<path
					d="M 96,16 L 96,28 L 84,40 L 54,40 L 54,28 L 84,28 Z"
					fill="currentColor"
				/>
				<path
					d="M 54,40 L 66,40 L 66,64 L 78,64 L 54,88 Z"
					fill="currentColor"
				/>
			</svg>
			{withWordmark && (
				<span
					style={{
						fontFamily:
							"var(--font-display, ui-sans-serif, system-ui, sans-serif)",
						fontWeight: 600,
						fontSize: wordmarkPx,
						letterSpacing: "-0.025em",
						textTransform: "lowercase",
						lineHeight: 1,
					}}
				>
					tracelane
				</span>
			)}
		</span>
	);
}
