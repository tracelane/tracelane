/**
 * RangeControl — a shared time-range segment (24h / 7d / 30d) that drives a
 * server-rendered page via the `?range=` URL param. Server-driven (updates the
 * URL, the RSC re-fetches) — never a client-only illusion. Used by Dashboard,
 * SLO, and Gateway so the range control is consistent across surfaces.
 *
 * Smoothness (founder: "changing 24h→30d refetches the whole page, feels slow"):
 * the navigation runs inside `useTransition`, so React KEEPS the current view on
 * screen and swaps in the new data when it arrives — no unmount, no "Loading…"
 * flash (the page's Suspense boundary must NOT be keyed on `range`). The clicked
 * pill highlights OPTIMISTICALLY (instant feedback) and the control shows a quiet
 * pending state while the RSC re-fetches — the Instagram/Meta feel.
 */
"use client";

import { useNavProgress } from "@/components/NavProgress";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, useTransition } from "react";

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
	const [isPending, startTransition] = useTransition();
	const { setPending } = useNavProgress();
	// Optimistic selection: highlight the clicked pill immediately, before the
	// URL/RSC catches up. Reset whenever the committed range changes (navigation
	// finished, or the user hit back) via React's render-time state-reset pattern
	// — no effect needed.
	const [optimistic, setOptimistic] = useState<string | null>(null);
	const [seenUrl, setSeenUrl] = useState<string | null>(null);
	const urlRange = sp.get("range") ?? defaultRange;
	if (seenUrl !== urlRange) {
		setSeenUrl(urlRange);
		setOptimistic(null);
	}
	const active = optimistic ?? urlRange;

	const hrefFor = (v: string) => {
		const p = new URLSearchParams(sp.toString());
		p.set("range", v);
		return `${pathname}?${p.toString()}`;
	};

	// Surface the transition's pending state to the global top loading bar (the
	// visible "loading" sign the founder asked for — the view itself stays put).
	useEffect(() => {
		setPending(isPending);
	}, [isPending, setPending]);

	// Prefetch every range on mount so a click swaps in the (mostly) prefetched
	// RSC payload — the Grafana/Vercel "feels instant" trick. Hover reinforces it.
	// Inlined (not via hrefFor) so the deps are exactly pathname/sp/router.
	useEffect(() => {
		const qs = sp.toString();
		for (const o of PRESETS) {
			const p = new URLSearchParams(qs);
			p.set("range", o.v);
			router.prefetch(`${pathname}?${p.toString()}`);
		}
	}, [pathname, sp, router]);

	const set = (v: string) => {
		if (v === active) return;
		setOptimistic(v); // instant pill feedback (outside the transition)
		// The transition keeps the current page visible while the RSC re-fetches.
		startTransition(() => router.push(hrefFor(v)));
	};

	return (
		<div
			aria-busy={isPending}
			className={`inline-flex items-center rounded-md border border-line p-0.5 transition-opacity duration-150 ${isPending ? "opacity-60" : ""}`}
		>
			<span className="sr-only">Time range</span>
			{PRESETS.map((o) => (
				<button
					key={o.v}
					type="button"
					onClick={() => set(o.v)}
					onMouseEnter={() => router.prefetch(hrefFor(o.v))}
					aria-pressed={active === o.v}
					className={
						active === o.v
							? "rounded px-2.5 py-1 text-xs font-medium bg-selected text-selected-on"
							: "rounded px-2.5 py-1 text-xs font-medium text-ink-2 hover:text-ink"
					}
				>
					{o.l}
				</button>
			))}
		</div>
	);
}
