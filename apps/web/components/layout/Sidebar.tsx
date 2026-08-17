"use client";

/**
 * Sidebar — the app's primary navigation (ADR-074 §6). Replaces the 11-item
 * horizontal top bar, which did not scale and already ran edge to edge.
 *
 * NINE ITEMS, THREE GROUPS, NO SCROLL: Observe · Prove · Operate, with Settings and
 * the account menu below the rule. `Prove` is its own group deliberately — the
 * tamper-evident ledger is the moat, and it was buried.
 *
 * NO NEW DEPENDENCIES, AND THE §9 CARVE-OUT WAS NOT NEEDED. Founder ruling R4 amended
 * "no new JS dependencies" specifically to allow shadcn's `Sidebar`. It is not used:
 * shadcn's sidebar is ~700 lines over FOUR Radix packages (Slot, Dialog for the mobile
 * sheet, Tooltip for the rail, Separator), and this repo has ZERO Radix, no
 * `components.json` and no shadcn install at all. Everything §6 actually asks for —
 * 240px/rail collapse, a cookie read server-side so there is no flash, tooltips on the
 * rail, a mobile drawer — is plain React and CSS. Taking the carve-out would have added
 * four runtime dependencies to render a list of links. The licence stays unspent.
 *
 * NO FLASH, AND THAT IS THE ONE HARD PART. The collapsed state lives in a
 * `sidebar_state` cookie READ ON THE SERVER in `app/layout.tsx` and passed down as
 * `defaultCollapsed`, so the first painted frame is already correct. Reading it in a
 * `useEffect` would render expanded and then snap — the flash §6 calls out. Radix would
 * not have helped here either; this is a server-render problem, not a component one.
 */

import { Logo, cn } from "@tracelanedev/ui";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { AccountMenu } from "./AccountMenu";
import { sections } from "./nav-config";
import { shortLabel } from "./nav-model";

const COOKIE = "sidebar_state";

/** Groups that belong on the rail, in order. Settings is rendered separately below. */
const PRIMARY_SECTIONS = sections.filter((s) => s.label !== "Settings");

function persist(collapsed: boolean) {
	// 1 year, root path. Same-site by default; this is UI state, not a credential.
	document.cookie = `${COOKIE}=${collapsed ? "collapsed" : "expanded"};path=/;max-age=31536000;samesite=lax`;
}

function ChevronIcon({ collapsed }: { collapsed: boolean }) {
	return (
		<svg
			viewBox="0 0 16 16"
			width="16"
			height="16"
			fill="none"
			stroke="currentColor"
			strokeWidth="1.6"
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
			className={cn("transition-transform", collapsed && "rotate-180")}
		>
			<path d="M10 3.5 5.5 8l4.5 4.5" />
		</svg>
	);
}

export function Sidebar({
	defaultCollapsed = false,
}: {
	defaultCollapsed?: boolean;
}) {
	const pathname = usePathname();
	const [collapsed, setCollapsed] = useState(defaultCollapsed);
	const [mobileOpen, setMobileOpen] = useState(false);

	// The trace-detail route defaults to collapsed (ADR-074 §6): 240px is ~16% of a
	// 1440px viewport and it compresses the waterfall directly. Only applied on
	// ENTERING the route, and only when the user has not pinned a preference — a
	// nav that fights an explicit choice is worse than one that never helps.
	const isTraceDetail = /^\/traces\/[^/]+$/.test(pathname);
	useEffect(() => {
		if (isTraceDetail && !document.cookie.includes(`${COOKIE}=`)) {
			setCollapsed(true);
		}
	}, [isTraceDetail]);

	const toggle = useCallback(() => {
		setCollapsed((c) => {
			persist(!c);
			return !c;
		});
	}, []);

	const isActive = (href: string) =>
		pathname === href || pathname.startsWith(`${href}/`);

	const width = collapsed ? "w-14" : "w-60";

	const nav = (
		<nav
			aria-label="Primary navigation"
			className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto"
		>
			{PRIMARY_SECTIONS.map((section) => (
				<div key={section.label} className="flex flex-col gap-0.5">
					{/* Small-caps section labels are kept from the previous app —
					    ADR-074 §4 says that instinct was right. Hidden on the rail,
					    where the group is read from the gap instead. */}
					{!collapsed && (
						<div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-ink-3">
							{section.label}
						</div>
					)}
					{section.items.map(({ href, label: rawLabel, Icon }) => {
						const active = isActive(href);
						// ADR-074 §6 names these "Signatures" and "SLO".
						const label = shortLabel(href, rawLabel);
						return (
							<Link
								key={href}
								href={href}
								aria-current={active ? "page" : undefined}
								title={collapsed ? label : undefined}
								onClick={() => setMobileOpen(false)}
								className={cn(
									"flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors",
									collapsed && "justify-center px-0",
									active
										? "bg-selected text-selected-on"
										: "text-ink-2 hover:bg-surface-2 hover:text-ink",
								)}
							>
								<span className="shrink-0">
									<Icon />
								</span>
								{!collapsed && <span className="truncate">{label}</span>}
							</Link>
						);
					})}
				</div>
			))}
		</nav>
	);

	return (
		<>
			{/* Mobile trigger lives in the top bar; this is the drawer it opens. */}
			{mobileOpen && (
				<button
					type="button"
					aria-label="Close navigation"
					onClick={() => setMobileOpen(false)}
					className="fixed inset-0 z-40 bg-black/40 lg:hidden"
				/>
			)}

			<aside
				data-sidebar
				data-collapsed={collapsed ? "true" : "false"}
				className={cn(
					// `sticky top-0 h-screen` is what makes Settings / Account / Collapse
					// visible WITHOUT SCROLLING. Before this the aside was a flex child of a
					// `min-h-screen` row, so it grew to the height of the PAGE — on a long
					// dashboard its footer sat two screens down, and the founder had to scroll
					// the whole page to reach Settings. The rail is chrome; chrome does not
					// scroll away. The nav scrolls inside itself if nine items ever outgrow a
					// short viewport, and `mt-auto` pins the footer to the bottom of the
					// VIEWPORT rather than the bottom of the document.
					"sticky top-0 z-50 flex h-screen shrink-0 flex-col gap-3 overflow-hidden border-line border-r bg-canvas-sunken px-2 py-3 transition-[width] duration-150",
					width,
					// Mobile: off-canvas drawer, always full width when open.
					"max-lg:fixed max-lg:inset-y-0 max-lg:left-0 max-lg:h-full max-lg:w-60",
					mobileOpen ? "max-lg:flex" : "max-lg:hidden",
				)}
			>
				<div
					className={cn(
						"flex items-center gap-2 px-1",
						collapsed && "justify-center px-0",
					)}
				>
					<Link
						href="/dashboard"
						aria-label="Tracelane — dashboard"
						className="flex items-center rounded-md outline-none"
					>
						<Logo withWordmark={!collapsed} height={22} />
					</Link>
				</div>

				{nav}

				<div className="mt-auto flex shrink-0 flex-col gap-0.5 border-line border-t pt-2">
					<AccountMenu collapsed={collapsed} />
					<button
						type="button"
						onClick={toggle}
						aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
						aria-expanded={!collapsed}
						className={cn(
							"flex items-center gap-2.5 rounded-md px-2 py-1.5 text-ink-3 text-sm transition-colors hover:bg-surface-2 hover:text-ink",
							collapsed && "justify-center px-0",
						)}
					>
						<ChevronIcon collapsed={collapsed} />
						{!collapsed && <span>Collapse</span>}
					</button>
				</div>
			</aside>

			{/* The lg-hidden opener, rendered here so the drawer state stays local. */}
			<button
				type="button"
				aria-label="Open navigation"
				onClick={() => setMobileOpen(true)}
				/* shadow-lg, not shadow-rest: `--shadow-rest` is defined in :root and NOT
				   inside @theme (which closes at tokens.css:150), so `shadow-rest` was
				   never a Tailwind utility and emitted nothing — verified against the
				   built CSS, where .shadow-rest is absent while .shadow-2xl is present.
				   This button is `fixed` over scrolling content, which is the overlay
				   case ADR-074 §5 allows a shadow for, so it should actually have one. */
				className="fixed bottom-4 left-4 z-30 flex h-11 w-11 items-center justify-center rounded-full border border-line bg-surface text-ink shadow-lg lg:hidden"
			>
				<svg
					viewBox="0 0 16 16"
					width="18"
					height="18"
					fill="none"
					stroke="currentColor"
					strokeWidth="1.6"
					strokeLinecap="round"
					aria-hidden="true"
				>
					<path d="M2.5 4h11M2.5 8h11M2.5 12h11" />
				</svg>
			</button>
		</>
	);
}
