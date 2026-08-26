"use client";

/**
 * AccountMenu — Settings, Support and Sign out, in the sidebar footer (ADR-074 §6:
 * "Settings · account", and "Support moves into the account menu").
 *
 * THIS IS NEW CONSTRUCTION, NOT A RELOCATION. The R12 before-inventory established
 * that the app has NO per-user account menu at all — `OrgSwitcher.tsx:36-38` says so
 * in as many words ("there is no per-user account menu — the account lives under
 * Settings"). The old bar had a bare `Sign out` anchor and nothing else, so ADR-074's
 * instruction to "move Support into the account menu" had no menu to move it into.
 * It is built here so that nothing the top bar carried is dropped on the floor —
 * Support in particular had a nav entry and would otherwise have become unreachable.
 *
 * Plain React: a details/summary disclosure, which is what buys the toggle, the
 * keyboard activation and the expanded/collapsed semantics without a menu
 * primitive.
 *
 * **Corrected 2026-08-18.** This comment used to also credit `<details>` with
 * "Escape, and click-outside-to-close from the platform". It gives NEITHER — the
 * element toggles on click/Enter/Space and does nothing else. The claim was the
 * only place either behaviour existed, so an open account menu could be closed
 * only by clicking `Account` again. `useDismiss` supplies both, and is shared
 * with `NotificationBell`, which had the same hole.
 */

import { useDismiss } from "@/lib/use-dismiss";
import { cn } from "@tracelanedev/ui";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
	RAIL_ICON,
	RAIL_ITEM,
	RAIL_ITEM_ACTIVE,
	RAIL_ITEM_IDLE,
} from "./nav-config";
import { SETTINGS_HREF, SUPPORT_HREF } from "./nav-model";

function GearIcon() {
	return (
		<svg
			viewBox="0 0 16 16"
			width="16"
			height="16"
			fill="none"
			stroke="currentColor"
			strokeWidth="1.5"
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
		>
			<circle cx="8" cy="8" r="2.25" />
			<path d="M8 1.5v1.7M8 12.8v1.7M14.5 8h-1.7M3.2 8H1.5M12.6 3.4l-1.2 1.2M4.6 11.4l-1.2 1.2M12.6 12.6l-1.2-1.2M4.6 4.6 3.4 3.4" />
		</svg>
	);
}

/**
 * The footer rows are the SAME rail rows as the nav above them (P0.13), so they
 * import the shared vocabulary from `nav-config` instead of restating it. The
 * local row constant that used to live here hand-wrote its own padding, radius
 * and the solid ink active pill, in parallel with `Sidebar` writing a second copy
 * of both — two definitions of one row, either of which could be restyled alone.
 * `RAIL_ITEM` carries the taller target and the control radius; `RAIL_ITEM_ACTIVE`
 * carries the subtle tone step that replaced the pill, and the measurement behind
 * that pair is written beside it in `nav-config.tsx`.
 */

export function AccountMenu({ collapsed = false }: { collapsed?: boolean }) {
	const pathname = usePathname();
	const settingsActive = pathname.startsWith("/settings");

	// `<details open>` is the source of truth for what is rendered; this state
	// only mirrors it so the dismiss listeners can be subscribed while open and
	// torn down while closed. `onToggle` is the element's own event, so the two
	// cannot drift — including when the user closes it by clicking the summary.
	const [menuOpen, setMenuOpen] = useState(false);
	const detailsRef = useDismiss<HTMLDetailsElement>(menuOpen, () => {
		if (detailsRef.current) detailsRef.current.open = false;
		setMenuOpen(false);
	});

	return (
		<>
			<Link
				href={SETTINGS_HREF}
				title={collapsed ? "Settings" : undefined}
				aria-current={settingsActive ? "page" : undefined}
				className={cn(
					RAIL_ITEM,
					collapsed && "justify-center px-0",
					settingsActive ? RAIL_ITEM_ACTIVE : RAIL_ITEM_IDLE,
				)}
			>
				<span className={RAIL_ICON}>
					<GearIcon />
				</span>
				{!collapsed && <span>Settings</span>}
			</Link>

			<details
				ref={detailsRef}
				className="group"
				onToggle={(e) => setMenuOpen(e.currentTarget.open)}
			>
				<summary
					title={collapsed ? "Account" : undefined}
					className={cn(
						RAIL_ITEM,
						RAIL_ITEM_IDLE,
						"cursor-pointer list-none",
						collapsed && "justify-center px-0",
					)}
				>
					<span className={RAIL_ICON}>
						<svg
							viewBox="0 0 16 16"
							width="16"
							height="16"
							fill="none"
							stroke="currentColor"
							strokeWidth="1.5"
							strokeLinecap="round"
							aria-hidden="true"
						>
							<circle cx="8" cy="5.5" r="2.75" />
							<path d="M2.75 13.5a5.25 5.25 0 0 1 10.5 0" />
						</svg>
					</span>
					{!collapsed && <span>Account</span>}
				</summary>
				<div className="mt-0.5 flex flex-col gap-0.5 pl-1">
					{/*
					 * `title` when collapsed, exactly as every other rail row does it.
					 * WITHOUT IT THESE TWO LINKS HAVE NO ACCESSIBLE NAME AT ALL on the
					 * rail: the icon slot renders an EMPTY span (there is no submenu
					 * glyph, deliberately — the labels line up under `Account`), and
					 * `{!collapsed && …}` suppresses the text, so a screen reader and a
					 * tooltip both got nothing and the control announced as "link".
					 * Sibling rows never had this hole because each carries a real icon
					 * plus `title={collapsed ? label : undefined}`; these two were built
					 * from the row vocabulary without the one part that was doing the
					 * work. Found by the P0 accessibility audit, 2026-08-22.
					 */}
					<Link
						href={SUPPORT_HREF}
						title={collapsed ? "Support" : undefined}
						className={cn(RAIL_ITEM, RAIL_ITEM_IDLE)}
					>
						{/* An empty icon slot on the SAME fixed column, so the submenu's
						    labels line up under Account's instead of sitting 2.5 units
						    left of it. `RAIL_ICON` is the one definition of that column. */}
						<span className={RAIL_ICON} />
						{!collapsed && <span>Support</span>}
					</Link>
					<a
						href="/sign-out"
						title={collapsed ? "Sign out" : undefined}
						className={cn(RAIL_ITEM, RAIL_ITEM_IDLE)}
					>
						<span className={RAIL_ICON} />
						{!collapsed && <span>Sign out</span>}
					</a>
				</div>
			</details>
		</>
	);
}
