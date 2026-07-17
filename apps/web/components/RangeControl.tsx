/**
 * RangeControl — a shared time-range segment (24h / 7d / 30d) that drives a
 * server-rendered page via the `?range=` URL param. Server-driven (updates the
 * URL, the RSC re-fetches) — never a client-only illusion. Used by Dashboard,
 * SLO, and Gateway so the range control is consistent across surfaces.
 *
 * The RSC reads `searchParams.range` and threads it through EVERY fetch (and,
 * where cards click through, every href) via `rangeToHours` — so the numbers and
 * the drill-throughs stay on the same window.
 */
"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

const PRESETS = [
	{ v: "24h", l: "24h" },
	{ v: "7d", l: "7d" },
	{ v: "30d", l: "30d" },
] as const;

export const DEFAULT_RANGE = "24h";

/**
 * @param defaultRange the preset a page treats as its no-param default (so the
 *   active pill matches the data window). Sessions uses "30d" because sessions
 *   are sparse aggregates — a 24h default reads as "empty" on low traffic; most
 *   surfaces keep 24h.
 */
export function RangeControl({
	defaultRange = DEFAULT_RANGE,
}: {
	defaultRange?: string;
} = {}) {
	const router = useRouter();
	const pathname = usePathname();
	const sp = useSearchParams();
	const active = sp.get("range") ?? defaultRange;

	const set = (v: string) => {
		const p = new URLSearchParams(sp.toString());
		p.set("range", v);
		router.push(`${pathname}?${p.toString()}`);
	};

	return (
		<div className="inline-flex items-center rounded-md border border-line p-0.5">
			<span className="sr-only">Time range</span>
			{PRESETS.map((o) => (
				<button
					key={o.v}
					type="button"
					onClick={() => set(o.v)}
					aria-pressed={active === o.v}
					className={
						active === o.v
							? "rounded px-2.5 py-1 text-xs font-medium bg-surface-2 text-ink"
							: "rounded px-2.5 py-1 text-xs font-medium text-ink-2 hover:text-ink"
					}
				>
					{o.l}
				</button>
			))}
		</div>
	);
}
