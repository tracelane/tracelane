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
 *
 * ── P0.13 REFINEMENT (2026-08-22) ────────────────────────────────────────────
 * The brief calls the rail one of the strongest things in the product, so this pass
 * is refinement only: the grouping, every destination, the collapse behaviour and the
 * no-flash cookie are untouched. What changed, and why:
 *
 *   · THE PLANE IS SOLID `--sidebar`, NOT `.glass`. Glass is sanctioned for chrome,
 *     but it buys nothing here and costs a compositor pass: the rail is a full-height
 *     `sticky` COLUMN BESIDE the content, not a bar ON TOP of it, so nothing ever
 *     scrolls underneath it — `backdrop-filter` re-samples a static canvas every
 *     frame to reveal a static canvas. `--sidebar` is a real token now (#fcfcfb /
 *     #101113: one step off the page ground in each theme), so a solid plane plus a
 *     `--line` hairline separates the rail more crisply than an 82%-opaque wash did,
 *     and it is cheaper. The TopBar keeps `.glass` — content genuinely passes under
 *     that one.
 *   · THE ACTIVE ROW IS A TONE STEP, NOT AN INK PILL. It was `--selected` /
 *     `--selected-on`: solid black with a white label, which the brief names as the
 *     thing to remove. The replacement pair and the measurement behind it are in
 *     `nav-config.tsx` beside `RAIL_ITEM_ACTIVE` — including why the obvious token
 *     pair inverts in dark.
 *   · ICONS SIT ON A FIXED COLUMN (`RAIL_ICON`), so labels start at the same x
 *     regardless of glyph width, and the touch target grew from `py-1.5` to `py-2`.
 */

import { Logo, cn } from "@tracelanedev/ui";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { AccountMenu } from "./AccountMenu";
import {
	RAIL_GROUP_LABEL,
	RAIL_ICON,
	RAIL_ITEM,
	RAIL_ITEM_ACTIVE,
	RAIL_ITEM_IDLE,
	sections,
} from "./nav-config";
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

/**
 * The 2px leading-edge state marker on the active row. It is the cheapest signal
 * that survives everything the tone step does not: a 7%-luminance background is
 * legitimately hard to see on a dim laptop panel, and this reads at a glance
 * without adding a colour. Tertiary ink rather than primary — the marker is meant
 * to be noticed after the label, not before it.
 *
 * `inset-y-1` insets it from the row's own top and bottom so it reads as a marker
 * on the row rather than as a divider between rows, and it is drawn for the
 * collapsed rail too, where the tone step is the only other cue.
 */
function ActiveMarker() {
	return (
		<span
			aria-hidden="true"
			className="pointer-events-none absolute inset-y-1 left-0 w-0.5 rounded-full bg-ink-3"
		/>
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
			// `gap-5` between groups, up from `gap-4`: P0.13 asks for more air above
			// each group heading, and the gap is what carries the grouping on the
			// collapsed rail where the headings are not rendered at all.
			className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto"
		>
			{PRIMARY_SECTIONS.map((section) => (
				<div key={section.label} className="flex flex-col gap-0.5">
					{/* Small-caps section labels are kept from the previous app —
					    ADR-074 §4 says that instinct was right. Hidden on the rail,
					    where the group is read from the gap instead. The type is
					    `RAIL_GROUP_LABEL`; the reasoning for 11px/tertiary ink over
					    the scale's page-level eyebrow is written there. */}
					{!collapsed && (
						<div className={RAIL_GROUP_LABEL}>{section.label}</div>
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
									RAIL_ITEM,
									collapsed && "justify-center px-0",
									active ? RAIL_ITEM_ACTIVE : RAIL_ITEM_IDLE,
								)}
							>
								{active && <ActiveMarker />}
								<span className={RAIL_ICON}>
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
					//
					// The plane is the solid `--sidebar` token plus a `--line` right edge,
					// NOT the translucent chrome class it carried until 2026-08-22 — the
					// header comment explains why glass had no payoff on a column nothing
					// scrolls under.
					//
					// `transition-[width]` is the ONE transition in the app on a layout
					// property — width animates through layout+paint every frame, and it
					// reflows the whole page beside it, not just the rail. It is kept
					// deliberately: collapsing the rail has to give the main column its
					// pixels back, and the transform-based alternatives (translating the
					// rail off-canvas) change what "collapsed" means on desktop. What it
					// gets instead is `motion-reduce:transition-none` — the page content
					// physically travels here, which is exactly the movement class
					// `prefers-reduced-motion` exists to suppress. Collapsed/expanded is
					// unchanged; only the 150ms of travel between them is dropped.
					"sticky top-0 z-50 flex h-screen shrink-0 flex-col gap-3 overflow-hidden border-line border-r bg-sidebar px-2 py-3 transition-[width] duration-150 motion-reduce:transition-none",
					width,
					// Mobile: off-canvas drawer, always full width when open.
					"max-lg:fixed max-lg:inset-y-0 max-lg:left-0 max-lg:h-full max-lg:w-60",
					mobileOpen ? "max-lg:flex" : "max-lg:hidden",
				)}
			>
				{/* `pb-3` on the LOGO block, not a bigger column `gap`: the column's
				    gap-3 also separates nav from the footer, so widening it would
				    push the account menu around too. This adds breathing room in
				    exactly one place — between the wordmark and the first section
				    label — which is what the sidebar had spare. It is a rem value,
				    so it scales with the ADR-074 `:root` clamp like everything else
				    rather than pinning a pixel gap at one viewport. */}
				<div
					className={cn(
						"flex items-center gap-2 px-1 pb-3",
						collapsed && "justify-center px-0",
					)}
				>
					<Link
						href="/dashboard"
						aria-label="Tracelane — dashboard"
						className="flex items-center rounded-[var(--radius-control)]"
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
							RAIL_ITEM,
							RAIL_ITEM_IDLE,
							collapsed && "justify-center px-0",
						)}
					>
						<span className={RAIL_ICON}>
							<ChevronIcon collapsed={collapsed} />
						</span>
						{!collapsed && <span>Collapse</span>}
					</button>
				</div>
			</aside>

			{/* The lg-hidden opener, rendered here so the drawer state stays local. */}
			<button
				type="button"
				aria-label="Open navigation"
				onClick={() => setMobileOpen(true)}
				/* `--shadow-overlay`, not the stock Tailwind drop this carried: the button
				   is `fixed` over scrolling content, which is the one elevation the system
				   paints a shadow for, and the token is the value that elevation is defined
				   at in both themes. It replaces the default-scale class for the same
				   reason that class replaced `shadow-rest` — a shadow that is not the
				   system's shadow is a fourth elevation nobody declared. The old class name
				   is DESCRIBED rather than quoted, because Tailwind extracts candidates from
				   comments too and would keep emitting a rule nothing wears.

				   It stays `rounded-full`: the chrome's other floating chips (the theme
				   toggle, the workspace pill) are circles/pills, and a lone 8px-cornered
				   square among them would read as a different component, not a tidier one. */
				className="fixed bottom-4 left-4 z-30 flex h-11 w-11 items-center justify-center rounded-full border border-line bg-surface text-ink shadow-[var(--shadow-overlay)] lg:hidden"
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
