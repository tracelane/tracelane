import { cn } from "../lib/cn";

export interface LogoProps {
	/** pixel height of the mark (and the lockup). Default 26 — the marketing-site size. */
	height?: number;
	/** render the full lockup (mark + "tracelane" wordmark); else just the mark. */
	withWordmark?: boolean;
	className?: string;
}

/**
 * Tracelane brand lockup — the **aperture** mark + "tracelane" wordmark.
 *
 * THE MARK. Four crop corners capturing a centre, with a span entering from both
 * edges. Founder's brief: "a span captured in a box, concentric circles in centre".
 *
 * ── THIS FILE IS THE THIRD OF THREE, AND THEY MUST AGREE ────────────────────────
 * The same geometry exists in exactly three places, one per language, because no
 * generator can emit an Astro component, a React component AND a PNG:
 *
 *   apps/site/src/components/Logo.astro     the marketing header (shipped first)
 *   packages/ui/src/primitives/Logo.tsx     this file — the app header
 *   scripts/brand/build-brand-assets.py     every PNG/ICO/SVG in brand/
 *
 * The numbers below are the Astro component's numbers, transcribed. The generator
 * expands the same numbers onto its own canvas. **If the mark changes, it changes in
 * all three** — that is the cost of the mark existing in three runtimes, and it is
 * why `scripts/ci/check-retired-logo.py` exists at all: the previous replacement
 * updated the generated assets and left FIVE components rendering the dead mark in
 * production overnight.
 *
 * It deliberately does NOT reuse the retired chisel bracket-recorder's geometry
 * (ADR-074 §8, "dead; do not resurrect it from any spec"), and the guard's two
 * signatures are not quoted here on purpose — it scans raw text, so writing the
 * pattern out to explain it is itself a hit.
 *
 * ── OPTICAL SIZING, and it is not decoration ────────────────────────────────────
 * A ring-and-ring centre COLLAPSES at small sizes: three concentric bands cannot each
 * hold ~1.2px inside 16px. Below `SMALL_AT` the mark drops to a simplified cut —
 * thicker corners, one solid centre, no rings. Same silhouette, legible where the
 * full cut is mush. The generator's `--selftest` measures that threshold from the
 * ring geometry and asserts it in both directions; this file adopts the number it
 * proves rather than restating a judgement.
 *
 * Monochrome per the logo lock via `currentColor` → `--logo-ink`, which tracks
 * `--ink` in both themes and is never coloured (ADR-074 §8). `--logo-ink` is
 * `#171717` light / `#f5f5f5` dark (`packages/ui/src/styles/tokens.css`), and
 * `--font-display` is Geist — the lockup is sans.
 */

/** Below this rendered px the simplified cut is used. Proven in the generator. */
const SMALL_AT = 20;

/** Four L-shaped crop corners. `arm` = leg length, `t` = stroke, on the 100×100 grid. */
function corners(arm: number, t: number): string[] {
	const i = 8 + t;
	return [
		`M 8,8 H ${8 + arm} V ${i} H ${i} V ${8 + arm} H 8 Z`,
		`M 92,8 H ${92 - arm} V ${i} H ${92 - t} V ${8 + arm} H 92 Z`,
		`M 8,92 H ${8 + arm} V ${92 - t} H ${i} V ${92 - arm} H 8 Z`,
		`M 92,92 H ${92 - arm} V ${92 - t} H ${92 - t} V ${92 - arm} H 92 Z`,
	];
}

export function Logo({
	height = 26,
	withWordmark = false,
	className,
}: LogoProps) {
	// Proportions locked to the site lockup: mark 26px ↔ wordmark 18px (size-lg)
	// ↔ gap 10px (gap-2.5). Scaled off `height` so any size stays true to spec.
	const wordmarkPx = Math.round(height * (18 / 26));
	const gapPx = Math.round(height * (10 / 26));
	const small = height < SMALL_AT;

	// The span. It STOPS AT THE BRACKET LINE rather than the canvas edge, which is
	// what keeps the mark's bounding box SQUARE (8..92 on both axes) — every square
	// surface (favicon, app icon, avatar) then centres it without hand-nudging, and
	// each bar ends exactly where the outer ring begins. In the small cut the centre
	// is a solid disc, so the bars run to ITS edge instead.
	const paths = small
		? [...corners(30, 14), "M 8,44 H 34 V 56 H 8 Z", "M 66,44 H 92 V 56 H 66 Z"]
		: [
				...corners(26, 12),
				"M 8,44 H 25.5 V 56 H 8 Z",
				"M 74.5,44 H 92 V 56 H 74.5 Z",
			];

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
				{paths.map((d) => (
					<path key={d} d={d} fill="currentColor" />
				))}
				{small ? (
					<circle cx="50" cy="50" r="16" fill="currentColor" />
				) : (
					<>
						<circle
							cx="50"
							cy="50"
							r="22"
							fill="none"
							stroke="currentColor"
							strokeWidth="7"
						/>
						<circle
							cx="50"
							cy="50"
							r="8.5"
							fill="none"
							stroke="currentColor"
							strokeWidth="6"
						/>
					</>
				)}
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
