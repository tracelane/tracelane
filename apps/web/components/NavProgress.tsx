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
 * bar animates an indeterminate lava sweep while pending.
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
		<div
			aria-hidden="true"
			className="pointer-events-none fixed inset-x-0 top-0 z-[100] h-[3px] overflow-hidden bg-accent-soft"
		>
			<div
				className="h-full w-1/3 rounded-full bg-accent shadow-[0_0_10px_var(--accent)]"
				style={{ animation: "nav-indeterminate 1.1s ease-in-out infinite" }}
			/>
		</div>
	);
}
