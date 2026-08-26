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
 *
 * PREFETCH POLICY — HOVER ONLY, and the reason is measured, not stylistic.
 * This control used to `router.prefetch()` all three presets from a mount effect.
 * Every preset is a FULL server render of the host page, so on a production build
 * (`next start`, local fixture gateway, 2026-08-22) one browser load cost:
 *
 *     /dashboard  33 gateway subrequests   (the page needs  8)  — 4.1×
 *     /slo        13 gateway subrequests   (the page needs  3)  — 4.3×
 *     /gateway     9 gateway subrequests   (the page needs  2)  — 4.5×
 *
 * plus 77.6 kB of extra transfer on /dashboard alone. One of the three renders is
 * the range ALREADY ON SCREEN — waste with no upside in any scenario — and another
 * is `range=30d`, the exact 906-row window this repo already blew the Cloudflare
 * Worker CPU ceiling on (Error 1102; see the `bucket=` note in
 * `app/dashboard/page.tsx`). Speculatively running that on every dashboard view is
 * the opposite of what that fix was for.
 *
 * What replaces it: `onOptionHover` below, which prefetches the ONE preset the
 * pointer is actually on. KNOWN LIMIT, stated because it is a real trade: the
 * primitive wires hover via `onMouseEnter` only, so a touch device gets no
 * prefetch and its range switch is a cold RSC fetch — covered by the
 * `useTransition` + optimistic pill + top progress bar above, which are what make
 * the wait legible. If touch prefetch is wanted back, prefetch the two INACTIVE
 * presets, never all three.
 */
"use client";

import { useNavProgress } from "@/components/NavProgress";
import { SegmentedControl } from "@tracelanedev/ui";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, useTransition } from "react";

const PRESETS = [
	{ value: "24h", label: "24h" },
	{ value: "7d", label: "7d" },
	{ value: "30d", label: "30d" },
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

	const set = (v: string) => {
		if (v === active) return;
		setOptimistic(v); // instant pill feedback (outside the transition)
		// The transition keeps the current page visible while the RSC re-fetches.
		startTransition(() => router.push(hrefFor(v)));
	};

	return (
		/*
		 * The well-with-a-lifted-segment treatment this control pioneered now lives
		 * in `SegmentedControl` (`@tracelanedev/ui`), which is where the nine
		 * hand-rolled copies of this pattern converged. The long note that used to
		 * sit here — including how the lift reads as an INSET in dark theme — moved
		 * with the markup it describes; it would be a comment about code that is no
		 * longer in this file.
		 *
		 * What stays here is the only part that is this control's own: the
		 * optimistic selection, the `useTransition` that keeps the current view on
		 * screen, and the HOVER prefetch (the mount-time prefetch of every preset is
		 * gone — the header block above carries the measurement that removed it).
		 */
		<SegmentedControl
			label="Time range"
			value={active}
			options={PRESETS}
			pending={isPending}
			onChange={set}
			onOptionHover={(v) => router.prefetch(hrefFor(v))}
		/>
	);
}
