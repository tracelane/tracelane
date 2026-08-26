"use client";

/**
 * AppShell — sidebar + thin top bar + full-bleed content (ADR-074 §6, §11).
 *
 * TWO THINGS CHANGED TOGETHER, AND THAT WAS DELIBERATE (§11). The topbar became a
 * left sidebar, AND the centred `mx-auto max-w-[1536px]` container was removed in the
 * same pass. Doing one without the other trades one waste of horizontal space for
 * another: the old shell spent ~220px of margin on each side of a 1920 screen while
 * the waterfall was cramped, and a sidebar added on top of that container would have
 * taken a further 240px from the same budget.
 *
 * Content is now full-bleed BESIDE the sidebar — no centred max-width wrapper. The
 * 151 columns the R12 inventory counted keep the width they had, minus the rail.
 *
 * NO FRAME, NO BLUR, NO BIG SHADOW. The floating rounded canvas with its
 * `shadow-[0_26px_60px...]` is gone: ADR-074 §5 permits exactly one shadow in the
 * system, on overlays only, and bans blur outright.
 *
 * Bare routes (onboarding, auth) render with no chrome at all, exactly as before —
 * the previous Sidebar returned null for /onboarding and the framed shell skipped it.
 */

import { NavProgressProvider, TopLoadingBar } from "@/components/NavProgress";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

function isBareRoute(pathname: string): boolean {
	return (
		pathname === "/onboarding" ||
		pathname.startsWith("/sign-in") ||
		pathname.startsWith("/auth")
	);
}

export function AppShell({
	orgSlot,
	defaultCollapsed = false,
	children,
}: {
	orgSlot?: ReactNode;
	defaultCollapsed?: boolean;
	children: ReactNode;
}) {
	const pathname = usePathname();

	// Full-screen, self-contained routes: no frame, no nav chrome.
	if (isBareRoute(pathname)) {
		return <div className="min-h-screen bg-canvas">{children}</div>;
	}

	return (
		<NavProgressProvider>
			<TopLoadingBar />
			<div className="flex min-h-screen bg-canvas">
				<Sidebar defaultCollapsed={defaultCollapsed} />
				<div className="flex min-w-0 flex-1 flex-col">
					<TopBar orgSlot={orgSlot} />
					{/*
					 * P0.15/P0.16 — the content ground, and the app's ONLY page gutter.
					 *
					 * `.app-canvas` is a REAL RULE now (tokens.css @layer components): it
					 * paints `--canvas` plus `--canvas-gradient` on this one large
					 * container. The previous comment here described a "160deg
					 * <=4%-saturation static wash" that was "defined in tokens.css" — by
					 * then neither half was true. The class had no definition ANYWHERE, so
					 * this element painted nothing and `--canvas-gradient` had no consumer;
					 * and the value it now carries is a flat 180deg ground, not a tinted
					 * wash, because the ground stopped being white and no longer needs one.
					 *
					 * THE PADDING IS RESPONSIVE AND THERE IS STILL NO MAX-WIDTH. A flat
					 * `px-5` gave a 1280px laptop and a 2560px monitor the same 20px gutter,
					 * so the wider the screen the more the content looked stuck to the rail.
					 * The ramp opens the gutter with the viewport while content stays
					 * FULL-BLEED beside the rail — deliberately, per §11: re-introducing a
					 * centred `max-w-*` wrapper is exactly the horizontal-space waste the
					 * sidebar migration removed, and the waterfall is the surface that pays
					 * for it. Vertical padding is `py-6` so the first card clears the sticky
					 * bar rather than touching it.
					 */}
					<main className="app-canvas min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8 xl:px-10">
						{children}
					</main>
				</div>
			</div>
		</NavProgressProvider>
	);
}
