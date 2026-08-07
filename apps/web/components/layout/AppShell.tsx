"use client";

/**
 * AppShell — the framed app chrome (app design system): a sky-blue page with a
 * floating rounded canvas that holds the TopNav + route content.
 *
 * visual-pass-01: the canvas is `.app-canvas` (tokens.css) rather than the flat
 * `bg-canvas` — a STATIC vertical gradient, with `--canvas` still painted
 * underneath as the fallback colour. Static only; the ADR-053 animated-gradient
 * ban stands.
 *
 * Reads the pathname (client) to stay OFF the full-screen routes — onboarding
 * and the auth pages render bare, exactly as the former Sidebar returned null
 * for /onboarding. The workspace-identity slot (OrgSwitcher, a server component)
 * is passed through to TopNav so this client component stays free of server-only
 * session/DB code.
 */

import { NavProgressProvider, TopLoadingBar } from "@/components/NavProgress";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { TopNav } from "./TopNav";

function isBareRoute(pathname: string): boolean {
	return (
		pathname === "/onboarding" ||
		pathname.startsWith("/sign-in") ||
		pathname.startsWith("/auth")
	);
}

export function AppShell({
	orgSlot,
	children,
}: {
	orgSlot?: ReactNode;
	children: ReactNode;
}) {
	const pathname = usePathname();

	// Full-screen, self-contained routes: no frame, no nav chrome.
	if (isBareRoute(pathname)) {
		return <div className="min-h-screen bg-bg">{children}</div>;
	}

	return (
		<NavProgressProvider>
			<TopLoadingBar />
			<div className="min-h-screen bg-bg">
				<div className="mx-auto max-w-[1536px] p-3 sm:p-5">
					<div className="app-canvas rounded-3xl p-3 shadow-[0_26px_60px_-26px_rgba(24,50,96,0.30)] sm:p-4">
						<TopNav orgSlot={orgSlot} />
						<main className="px-1 sm:px-2">{children}</main>
					</div>
				</div>
			</div>
		</NavProgressProvider>
	);
}
