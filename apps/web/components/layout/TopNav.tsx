"use client";

/**
 * TopNav — the horizontal top-menu navigation shell (app design system,
 * docs/design/tracelane-app-full.html). Replaces the former left Sidebar.
 *
 * Brand left · a single horizontal menu (the nav-config primary items + a
 * Settings entry, active = black pill) · right cluster: workspace identity
 * (orgSlot), the light/dark toggle, and sign-out. Below `lg` the menu collapses
 * to a hamburger dropdown carrying the same links. Nav set + active detection
 * mirror the previous Sidebar exactly (nav-config is the single source of truth,
 * guarded by nav-config.test.ts) so no route is dropped or dead.
 */

import { Logo } from "@tracelanedev/ui";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { type ReactNode, useEffect, useState } from "react";
import { ThemeToggle } from "./ThemeToggle";
import { sections } from "./nav-config";

// Primary items (Observe / Improve / Operate), flattened into the horizontal
// menu; Settings is a single entry pointing at its first pane.
const PRIMARY = sections
	.filter((s) => s.label !== "Settings")
	.flatMap((s) => s.items);
const SETTINGS_HREF = "/settings/api-keys";
const SUPPORT_HREF = "/support";

// Short display labels for the horizontal bar (the sidebar used longer ones).
function shortLabel(href: string, label: string): string {
	if (href === "/signatures") return "Signatures";
	if (href === "/slo") return "SLOs";
	return label;
}

function cn(...classes: (string | false | undefined | null)[]): string {
	return classes.filter(Boolean).join(" ");
}

function SignOutIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
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

function LifeBuoyIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<circle cx="12" cy="12" r="10" />
			<circle cx="12" cy="12" r="4" />
			<line x1="4.93" y1="4.93" x2="9.17" y2="9.17" />
			<line x1="14.83" y1="14.83" x2="19.07" y2="19.07" />
			<line x1="14.83" y1="9.17" x2="19.07" y2="4.93" />
			<line x1="4.93" y1="19.07" x2="9.17" y2="14.83" />
		</svg>
	);
}

function SettingsGearIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<circle cx="12" cy="12" r="3" />
			<path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
		</svg>
	);
}

function MenuIcon({ open }: { open: boolean }) {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-5 w-5"
			aria-hidden="true"
		>
			{open ? (
				<>
					<line x1="18" y1="6" x2="6" y2="18" />
					<line x1="6" y1="6" x2="18" y2="18" />
				</>
			) : (
				<>
					<line x1="3" y1="6" x2="21" y2="6" />
					<line x1="3" y1="12" x2="21" y2="12" />
					<line x1="3" y1="18" x2="21" y2="18" />
				</>
			)}
		</svg>
	);
}

/**
 * `orgSlot` is the server-rendered workspace-identity cluster (the OrgSwitcher),
 * passed from the layout so this client component stays free of server-only
 * session/DB code.
 */
export function TopNav({ orgSlot }: { orgSlot?: ReactNode }) {
	const pathname = usePathname();
	const [open, setOpen] = useState(false);

	// Close the mobile dropdown on navigation.
	// biome-ignore lint/correctness/useExhaustiveDependencies: pathname is the route-change trigger, not a body dependency
	useEffect(() => {
		setOpen(false);
	}, [pathname]);

	// Pre-onboarding users have no workspace yet — no nav chrome (matches the
	// former Sidebar behavior).
	if (pathname === "/onboarding") return null;

	const settingsActive = pathname.startsWith("/settings");

	const menuLink = (href: string, label: string, active: boolean) => (
		<Link
			key={href}
			href={href}
			className={cn(
				"rounded-lg px-3 py-1.5 text-[13.5px] font-medium transition-colors",
				active
					? "bg-surface-inverse text-ink-inverse"
					: "text-ink-2 hover:text-ink",
			)}
		>
			{label}
		</Link>
	);

	// Liquid-glass nav (founder): frosted, translucent chrome that content scrolls
	// UNDER. sticky+z-30+isolate makes it a floating stacking context above page
	// content — so the glass reads AND nothing in <main> can ever paint over the
	// brand. backdrop-blur is confined to this one small bar (the blur ban is
	// ADR-053:40, not ADR-051 — 051 is the billing/EE split; the old citation here
	// was wrong — and it keeps blur off the scrolling cards / 2000-span table); a
	// solid-ish bg-surface/85 fallback covers no-backdrop-filter browsers.
	// visual-pass-01 did NOT add or remove this blur: it predates the pass, and
	// the pass's "no blur" gate is about not introducing NEW blur surfaces.
	return (
		<div className="sticky top-2 z-30 isolate mb-5 flex items-center gap-3 rounded-2xl border border-line bg-surface/85 px-3 py-2 shadow-[0_1px_2px_rgba(24,50,96,0.05)] backdrop-blur-xl supports-[backdrop-filter]:bg-surface/70">
			<Link
				href="/dashboard"
				aria-label="Tracelane — dashboard"
				className="shrink-0 rounded-md px-1.5 outline-none"
			>
				<Logo withWordmark />
			</Link>

			{/* Desktop horizontal menu */}
			<nav
				aria-label="Primary navigation"
				className="mx-auto hidden items-center gap-0.5 rounded-xl bg-surface-2 p-1 lg:flex"
			>
				{PRIMARY.map((item) =>
					menuLink(
						item.href,
						shortLabel(item.href, item.label),
						pathname.startsWith(item.href),
					),
				)}
				{menuLink(SETTINGS_HREF, "Settings", settingsActive)}
				{menuLink(SUPPORT_HREF, "Support", pathname.startsWith("/support"))}
			</nav>

			{/* Right cluster */}
			<div className="ml-auto flex items-center gap-2 lg:ml-0">
				{orgSlot}
				<ThemeToggle compact />
				<a
					href="/sign-out"
					aria-label="Sign out"
					className="flex h-9 w-9 items-center justify-center rounded-full bg-surface-2 text-ink transition-colors hover:bg-surface-3 hover:text-ink"
				>
					<SignOutIcon />
				</a>
				<button
					type="button"
					onClick={() => setOpen((o) => !o)}
					aria-label={open ? "Close navigation menu" : "Open navigation menu"}
					aria-expanded={open}
					className="flex h-9 w-9 items-center justify-center rounded-full bg-surface-2 text-ink transition-colors hover:bg-surface-3 hover:text-ink lg:hidden"
				>
					<MenuIcon open={open} />
				</button>
			</div>

			{/* Mobile dropdown (< lg) — same links, icon + label list */}
			{open && (
				<nav
					aria-label="Primary navigation"
					className="absolute inset-x-3 top-16 z-50 flex flex-col gap-0.5 rounded-2xl border border-line bg-surface p-2 shadow-lg lg:hidden"
				>
					{PRIMARY.map(({ href, label, Icon }) => (
						<Link
							key={href}
							href={href}
							className={cn(
								"flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
								pathname.startsWith(href)
									? "bg-surface-inverse text-ink-inverse"
									: "text-ink-2 hover:bg-surface-2 hover:text-ink",
							)}
						>
							<Icon />
							<span>{shortLabel(href, label)}</span>
						</Link>
					))}
					<Link
						href={SETTINGS_HREF}
						className={cn(
							"flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
							settingsActive
								? "bg-surface-inverse text-ink-inverse"
								: "text-ink-2 hover:bg-surface-2 hover:text-ink",
						)}
					>
						<SettingsGearIcon />
						<span>Settings</span>
					</Link>
					<Link
						href={SUPPORT_HREF}
						className={cn(
							"flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
							pathname.startsWith("/support")
								? "bg-surface-inverse text-ink-inverse"
								: "text-ink-2 hover:bg-surface-2 hover:text-ink",
						)}
					>
						<LifeBuoyIcon />
						<span>Support</span>
					</Link>
					<a
						href="/sign-out"
						className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-ink-2 transition-colors hover:bg-surface-2 hover:text-ink"
					>
						<SignOutIcon />
						<span>Sign out</span>
					</a>
				</nav>
			)}
		</div>
	);
}
