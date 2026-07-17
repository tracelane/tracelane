"use client";

/**
 * Sidebar — primary navigation shell for the Tracelane dashboard.
 *
 * Renders the nav set defined in `./nav-config` (`sections`): /traces,
 * /sessions, /slo, /prompts, /audit, plus the Settings group
 * (/settings/{api-keys,providers,billing,byok,team,workspace}). Active route
 * is highlighted with a surface-2 fill and a 2.5px Lava left rule (ADR-053),
 * inset via box-shadow so there is no layout shift between active/inactive.
 *
 * Responsive (2026-07-08): desktop (md+) keeps the original static, fixed-width
 * left column verbatim. Mobile (< md) gets a fixed top bar with a hamburger that
 * opens the SAME nav as a slide-in drawer + backdrop, so a phone isn't handed a
 * 224px rail eating 60% of the viewport. All mobile chrome is `md:hidden` and the
 * aside reverts to `md:static` — the desktop layout is unchanged at md+.
 *
 * Uses Next.js Link for client-side navigation and usePathname for
 * active state detection. No external icon library — inline SVG
 * keeps the dependency surface minimal.
 */

import { SupportWidget } from "@/components/support/SupportWidget";
import { Logo } from "@tracelanedev/ui";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { type ReactNode, useEffect, useState } from "react";
import { ThemeToggle } from "./ThemeToggle";
import { sections } from "./nav-config";

// Inline SVG icon helpers — avoids lucide-react/heroicons dependency.
// The nav-item icons live in ./nav-config alongside the route list; only the
// account-footer + mobile-menu icons are local to the Sidebar runtime.

function LogOutIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
			<polyline points="16 17 21 12 16 7" />
			<line x1="21" y1="12" x2="9" y2="12" />
		</svg>
	);
}

function MenuIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-5 w-5"
			aria-hidden="true"
		>
			<line x1="3" y1="6" x2="21" y2="6" />
			<line x1="3" y1="12" x2="21" y2="12" />
			<line x1="3" y1="18" x2="21" y2="18" />
		</svg>
	);
}

/** Combine class strings, filtering falsy values. */
function cn(...classes: (string | false | undefined | null)[]): string {
	return classes.filter(Boolean).join(" ");
}

/**
 * Primary navigation sidebar. Active route detection uses `startsWith` so
 * nested routes (e.g. /traces/[traceId]) stay highlighted under the parent.
 *
 * `orgSlot` is a server-rendered workspace-identity element (the OrgSwitcher),
 * passed in from the layout so this client component stays free of server-only
 * session/DB code.
 */
export function Sidebar({ orgSlot }: { orgSlot?: ReactNode }) {
	const pathname = usePathname();
	const [open, setOpen] = useState(false);

	// Close the mobile drawer on navigation — a tap-through shouldn't leave the
	// overlay open on top of the new page. `pathname` is the trigger (the effect
	// re-runs on route change); it isn't read in the body.
	// biome-ignore lint/correctness/useExhaustiveDependencies: pathname is the route-change trigger, not a body dependency
	useEffect(() => {
		setOpen(false);
	}, [pathname]);

	// Pre-onboarding users have no org yet; the dashboard nav (and Next's
	// prefetch of org-gated routes like /settings/billing) must not render for
	// them. The onboarding wizard is full-screen and self-contained.
	if (pathname === "/onboarding") return null;

	return (
		<>
			{/* Mobile top bar (md:hidden) — hamburger + wordmark. Fixed so page
			    content scrolls beneath it; `main` carries a matching pt-14. */}
			<header className="md:hidden fixed inset-x-0 top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-bg px-4">
				<button
					type="button"
					onClick={() => setOpen(true)}
					aria-label="Open navigation menu"
					aria-expanded={open}
					className="rounded-md p-1.5 text-ink-2 transition-colors hover:bg-surface-2/50 hover:text-ink"
				>
					<MenuIcon />
				</button>
				<Link
					href="/traces"
					aria-label="Tracelane — go to traces"
					className="outline-none"
				>
					<Logo withWordmark />
				</Link>
			</header>

			{/* Backdrop behind the open drawer (mobile only). A button so it is
			    keyboard-dismissable and screen-reader-labelled. */}
			{open && (
				<button
					type="button"
					aria-label="Close navigation menu"
					onClick={() => setOpen(false)}
					className="md:hidden fixed inset-0 z-40 bg-black/40"
				/>
			)}

			<aside
				className={cn(
					// Shared visual box.
					"flex flex-col gap-1 border-r border-line bg-bg p-3",
					// Mobile: a fixed slide-in drawer.
					"fixed inset-y-0 left-0 z-50 w-64 overflow-y-auto transition-transform duration-200",
					open ? "translate-x-0" : "-translate-x-full",
					// Desktop (md+): the ORIGINAL static column — no fixed, no transform.
					"md:static md:z-auto md:w-56 md:min-h-screen md:shrink-0 md:translate-x-0 md:overflow-visible md:transition-none",
				)}
			>
				<Link
					href="/traces"
					aria-label="Tracelane — go to traces"
					className="px-3 py-2 rounded-md outline-none"
				>
					<Logo withWordmark />
				</Link>

				{orgSlot}

				<nav aria-label="Primary navigation" className="flex flex-col gap-4">
					{sections.map((section, si) => (
						// Sidebar sections are statically defined and never reorder.
						// Prefer the section label when present; fall back to a stable
						// "unlabeled" slot id for the headerless first section.
						<div key={section.label ?? `section-${si}`}>
							{section.label && (
								<p className="px-3 mb-1 text-[10px] font-semibold text-ink-3 uppercase tracking-wider">
									{section.label}
								</p>
							)}
							{section.items.map(({ href, label, Icon, badge }) => (
								<Link
									key={href}
									href={href}
									className={cn(
										"flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
										pathname.startsWith(href)
											? "bg-surface-2 text-ink shadow-[inset_2.5px_0_0_0_var(--accent)]"
											: "text-ink-2 hover:bg-surface-2/50 hover:text-ink",
									)}
								>
									<Icon />
									<span className="flex-1">{label}</span>
									{badge && (
										<span className="rounded border border-line px-1 py-0.5 text-[9px] font-medium uppercase tracking-wide text-ink-3">
											{badge}
										</span>
									)}
								</Link>
							))}
						</div>
					))}
				</nav>

				{/* Account footer — plain <a> (not <Link>) so the GET /sign-out side
				    effect fires only on a real click, never on prefetch/hover. */}
				<div className="mt-auto pt-3 border-t border-line">
					<ThemeToggle />
					<SupportWidget />
					<a
						href="/sign-out"
						className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-ink-2 hover:bg-surface-2/50 hover:text-ink transition-colors"
					>
						<LogOutIcon />
						Sign out
					</a>
				</div>
			</aside>
		</>
	);
}
