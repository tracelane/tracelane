"use client";

/**
 * NavProgress — a global top loading bar (GitHub/YouTube/Vercel style) that gives
 * an unmistakable "something is loading" signal during in-app navigations that
 * keep the current view (range changes, filters) via `useTransition`.
 *
 * Founder feedback: the range switch "shows no sign unless the user notices the
 * URL". A `useTransition` deliberately keeps the old page on screen (no Suspense
 * fallback), so we MUST surface the pending state ourselves. RangeControl (and
 * any transition-driven control) reports pending here via `useNavProgress()`; the
 * bar animates an indeterminate sweep of `--action` (the ink family — the system
 * has no accent colour) over an `--action-soft` track while pending.
 *
 * "an indeterminate lava sweep" is what this line said until 2026-08-22. Lava was
 * a colour the palette no longer contains and the `--lava-*` tokens are deleted;
 * the sweep had been ink for a while and the sentence had not noticed.
 *
 * A short show-delay (120ms) suppresses a flicker on instant/prefetched
 * navigations — the bar only appears if the work actually takes a beat.
 */

import {
	type ReactNode,
	createContext,
	useContext,
	useEffect,
	useState,
} from "react";

const NavProgressContext = createContext<{
	pending: boolean;
	setPending: (p: boolean) => void;
}>({ pending: false, setPending: () => {} });

/** Report / read the global navigation-pending state. */
export function useNavProgress() {
	return useContext(NavProgressContext);
}

export function NavProgressProvider({ children }: { children: ReactNode }) {
	const [pending, setPending] = useState(false);
	return (
		<NavProgressContext.Provider value={{ pending, setPending }}>
			{children}
		</NavProgressContext.Provider>
	);
}

/** The fixed top bar itself — render once, high in the tree. */
export function TopLoadingBar() {
	const { pending } = useNavProgress();
	const [show, setShow] = useState(false);

	// Only reveal the bar if the work outlives a short grace window — a
	// prefetched/instant switch shouldn't flash the bar.
	useEffect(() => {
		if (!pending) {
			setShow(false);
			return;
		}
		const t = setTimeout(() => setShow(true), 120);
		return () => clearTimeout(t);
	}, [pending]);

	if (!show) return null;
	return (
		<>
			<div
				aria-hidden="true"
				className="pointer-events-none fixed inset-x-0 top-0 z-[100] h-[3px] overflow-hidden bg-action-soft"
			>
				{/*
				 * THREE FIXES, 2026-08-17.
				 *
				 * 1. DROPPED the arbitrary 10px zero-offset box-shadow in `--action`.
				 *    That is a glow, and ADR-074 §5 names glows in its Never list —
				 *    tokens.css records `.cta-lava` being deleted for exactly this form.
				 *    Worse, it survived the ADR-074 value swap into an ink `--action` (#171717
				 *    on today's palette), so a "glow" painted a 10px BLACK halo on a white
				 *    page. It read as a smudge under the bar, not as light. The hex in this
				 *    paragraph was #0d0d0d when it was written and has since moved — it is
				 *    quoted as the value AT THE TIME, which is why the token name leads.
				 *
				 *    The class string is DESCRIBED here rather than quoted on purpose.
				 *    Tailwind's scanner extracts candidates from raw file bytes, comments
				 *    included, so quoting the utility kept generating its rule in the
				 *    built stylesheet with no element wearing it — dead CSS that also
				 *    makes "the glow is gone" look false to anyone grepping the output.
				 *    Caught by grepping the built sheet, not the source.
				 * 2. `ease-in-out` -> `linear`, via the class below. An indeterminate
				 *    sweep is constant motion; ease-in-out decelerates into each end of
				 *    the travel, so a bar that means "still working" visibly hesitated
				 *    twice per cycle. Constant motion takes `linear`.
				 * 3. The animation moved from an inline `style` to `.nav-sweep` in
				 *    globals.css, beside its own @keyframes — an inline style cannot be
				 *    overridden by a `prefers-reduced-motion` media query, and this is
				 *    the app's only transform-based INFINITE animation.
				 */}
				<div className="nav-sweep h-full w-1/3 rounded-full bg-action" />
			</div>
			{/*
			 * The bar itself is decorative and stays `aria-hidden`. But it was the ONLY
			 * loading signal, so a screen-reader user got NOTHING from a component whose
			 * stated job is "an unmistakable 'something is loading' signal" — the users
			 * who cannot see the bar were the ones it excluded. `useTransition` keeps the
			 * old view on screen deliberately, so there is no Suspense fallback to
			 * announce either.
			 *
			 * `<output>` carries an implicit `role="status"` / `aria-live="polite"`, so it
			 * announces on mount without interrupting and goes silent when the navigation
			 * lands. The element rather than `<span role="status">` because biome's
			 * `a11y/useSemanticElements` asks for it, and it is right to: the semantic
			 * element keeps the role even if the attribute is later edited away.
			 *
			 * It sits behind the same 120ms grace window as the bar, so an instant or
			 * prefetched switch stays silent instead of chattering on every range change.
			 */}
			<output className="sr-only">Loading…</output>
		</>
	);
}
