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
					{/* ADR-074 §5 G1 — container tint on the LARGE CONTENT CONTAINER, which is what
					    §5 describes. `.app-canvas` (the 160deg <=4%-saturation static wash) was
					    defined in tokens.css and applied NOWHERE; the tint had only ever reached
					    cards. This is the one large container in the app. */}
					<main className="app-canvas min-w-0 flex-1 px-5 py-5">
						{children}
					</main>
				</div>
			</div>
		</NavProgressProvider>
	);
}
