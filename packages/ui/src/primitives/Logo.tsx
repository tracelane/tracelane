import { cn } from "../lib/cn";

export interface LogoProps {
	/** pixel height of the mark (and the lockup). Default 26 — the marketing-site size. */
	height?: number;
	/** render the full lockup (Chisel mark + "tracelane" wordmark); else just the mark. */
	withWordmark?: boolean;
	className?: string;
}

/**
 * Tracelane brand lockup — the Chisel bracket-recorder mark + "tracelane"
 * wordmark, rendered IDENTICALLY to the marketing site
 * (`tracelane-site/src/components/Header.astro`): an inline SVG mark
 * (`viewBox 0 0 76 76`) at `height`px, `gap-2.5`, and the wordmark in the
 * display face — Source Serif 4, weight 600, size-lg, tracking-tight, lowercase.
 *
 * ONE source of truth so the app header and the site header can't drift (the
 * previous app logo was a separate PNG raster, which is why it looked
 * undersized/underweight). Monochrome per the logo lock via `currentColor` →
 * `--logo-ink` (#0c0d0f on light, off-white on dark; never colored, never
 * lava). The mark's bullseye knocks out to `--surface` (the header behind it).
 * The wordmark font comes from `--font-display` (the app wires Source Serif 4).
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
				viewBox="0 0 76 76"
				width={height}
				height={height}
				aria-hidden="true"
				style={{ display: "block", flexShrink: 0 }}
			>
				<path
					d="M30 14 L14 14 L14 62 L30 62 L30 56 L20 56 L20 20 L30 20 Z"
					fill="currentColor"
				/>
				<path
					d="M46 14 L62 14 L62 62 L46 62 L46 56 L56 56 L56 20 L46 20 Z"
					fill="currentColor"
				/>
				<rect x="20" y="36.4" width="36" height="3.2" fill="currentColor" />
				<circle
					cx="38"
					cy="38"
					r="9"
					fill="var(--surface)"
					stroke="currentColor"
					strokeWidth="3"
				/>
				<circle
					cx="38"
					cy="38"
					r="3.6"
					fill="none"
					stroke="currentColor"
					strokeWidth="2.6"
				/>
			</svg>
			{withWordmark && (
				<span
					style={{
						fontFamily: 'var(--font-display, "Source Serif 4", Georgia, serif)',
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
