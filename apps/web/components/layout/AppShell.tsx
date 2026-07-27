"use client";

/**
 * AppShell — the framed app chrome (app design system): a sky-blue page with a
 * floating rounded canvas that holds the TopNav + route content.
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
					<div className="rounded-3xl bg-canvas p-3 shadow-[0_26px_60px_-26px_rgba(40,60,90,0.35)] sm:p-4">
						<TopNav orgSlot={orgSlot} />
						<main className="px-1 sm:px-2">{children}</main>
					</div>
				</div>
			</div>
		</NavProgressProvider>
	);
}
