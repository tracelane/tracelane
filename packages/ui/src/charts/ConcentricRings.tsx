import { cn } from "../lib/cn";

/**
 * ConcentricRings — nested "where the time goes" rings (app design system,
 * docs/design/tracelane-app-full.html screen 1). Outer → inner components of a
 * whole (e.g. end-to-end ⊃ provider ⊃ gateway-overhead latency).
 *
 * Pure presentation: every `value` is a pre-formatted REAL number supplied by
 * the caller — the component fabricates nothing. Ring sizes are a fixed nested
 * metaphor (not proportional); the caller passes a `caption` stating the real
 * relationship (e.g. "gateway = 5% of the trip") so the visual never overclaims.
 *
 * COLOUR (P0.11, 2026-08-22). The outer bands are INERT containers for a number, so
 * they take the two well steps — `--surface-2` then `--surface-3` — and only the
 * innermost ring, the highlighted one, is a data MARK and takes `--chart-primary`.
 * The ramp was `--action-soft` / `--action-line` / `--action`, i.e. an accent scale on
 * something that is not an action.
 */

export interface ConcentricRing {
	/** Pre-formatted real value, e.g. "9.33s" / "444ms" / "—". */
	value: string;
	/** Short label, e.g. "end-to-end". */
	label: string;
}

export interface ConcentricRingsProps {
	/** Outer → inner. 2–3 rings (the innermost is the highlighted `--chart-primary` fill). */
	rings: ConcentricRing[];
	caption?: string;
	className?: string;
}

const OUTER = 176;

export function ConcentricRings({
	rings,
	caption,
	className,
}: ConcentricRingsProps) {
	const n = Math.min(rings.length, 3);
	const shown = rings.slice(0, n);

	return (
		<div className={cn("flex flex-col items-center gap-3", className)}>
			<div className="relative" style={{ width: OUTER, height: OUTER }}>
				{shown.map((r, i) => {
					const size = OUTER - i * 58;
					const top = (OUTER - size) / 2;
					const inner = i === n - 1;
					// Outer→inner value ramp toward the solid --chart-primary core.
					const bg = inner
						? "var(--chart-primary)"
						: i === 0
							? "var(--surface-2)"
							: "var(--surface-3)";
					// v0-VIZ-REVISIT (founder, 2026-07-20) — KEPT, and re-measured. Read the
					// attribution honestly: the CONTRAST defect it recorded was closed by the
					// 2026-08-22 palette swap, not by this edit. It said the core number was
					// white on the soft lava fill (#ff8566) at ~2.4:1, below AA; lava is
					// deleted, so that pairing no longer exists. What this edit adds is the
					// numbers, so the next reader does not have to re-derive them:
					//  · core  — `--surface` knocked out of `--chart-primary`: #ffffff on
					//    #202124 = 16.1:1 light, #151619 on #f2f2f2 = 16.1:1 dark. It is the
					//    token that inverts exactly as chart-primary does; there is no
					//    `--chart-primary-on`, and this file may not add one.
					//  · bands — `--ink` on `--surface-2` / `--surface-3`: 16.4:1 light,
					//    13.7:1 dark. Both clear AA comfortably because the bands stay near
					//    the CARD colour instead of becoming mid-greys, and that is the
					//    reason they are the well steps rather than `--chart-secondary`:
					//    chart-secondary would give a punchier ramp and put the band number
					//    at 4.10:1 in dark, i.e. under the 4.5:1 floor for 14px semibold.
					// STILL OPEN for the founder's rework: the rings are a fixed metaphor,
					// not proportional, so the picture still cannot be read as a magnitude.
					const valueColor = inner ? "var(--surface)" : "var(--ink)";
					const labelColor = inner ? "var(--surface)" : "var(--ink-3)";
					return (
						<div
							key={r.label}
							className="absolute left-1/2 flex -translate-x-1/2 flex-col items-center"
							style={{
								width: size,
								height: size,
								top,
								borderRadius: "50%",
								background: bg,
								justifyContent: inner ? "center" : "flex-start",
								paddingTop: inner ? 0 : 10,
							}}
						>
							<span
								className="font-mono text-ramp-14 font-semibold leading-none tabular-nums"
								style={{ color: valueColor }}
							>
								{r.value}
							</span>
							{inner && (
								<span
									className="mt-1 text-2xs leading-none"
									style={{ color: labelColor }}
								>
									{r.label}
								</span>
							)}
						</div>
					);
				})}
			</div>
			{/* Legend — the OUTER ring labels live here, not inside the rings: each
			    inner ring is drawn over the outer ring's label band and was clipping
			    them ("end-to-end" / "provider" were hidden). The innermost ring keeps
			    its own label (nothing overlaps it). */}
			{n > 1 && (
				<ul className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
					{shown.slice(0, n - 1).map((r, i) => (
						<li
							key={r.label}
							className="flex items-center gap-1.5 text-2xs text-ink-3"
						>
							<span
								className="h-2 w-2 shrink-0 rounded-full border border-line"
								style={{
									background: i === 0 ? "var(--surface-2)" : "var(--surface-3)",
								}}
							/>
							<span>{r.label}</span>
						</li>
					))}
				</ul>
			)}
			{caption && <p className="text-center text-2xs text-ink-3">{caption}</p>}
		</div>
	);
}
