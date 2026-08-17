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
 * Plain React: a details/summary disclosure. It gets keyboard support, Escape, and
 * click-outside-to-close from the platform, which is the entire reason a menu
 * primitive would otherwise have been imported.
 */

import { cn } from "@tracelanedev/ui";
import Link from "next/link";
import { usePathname } from "next/navigation";
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

const ROW =
	"flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors";

export function AccountMenu({ collapsed = false }: { collapsed?: boolean }) {
	const pathname = usePathname();
	const settingsActive = pathname.startsWith("/settings");

	return (
		<>
			<Link
				href={SETTINGS_HREF}
				title={collapsed ? "Settings" : undefined}
				aria-current={settingsActive ? "page" : undefined}
				className={cn(
					ROW,
					collapsed && "justify-center px-0",
					settingsActive
						? "bg-selected text-selected-on"
						: "text-ink-2 hover:bg-surface-2 hover:text-ink",
				)}
			>
				<span className="shrink-0">
					<GearIcon />
				</span>
				{!collapsed && <span>Settings</span>}
			</Link>

			<details className="group">
				<summary
					title={collapsed ? "Account" : undefined}
					className={cn(
						ROW,
						"cursor-pointer list-none text-ink-2 hover:bg-surface-2 hover:text-ink",
						collapsed && "justify-center px-0",
					)}
				>
					<span className="shrink-0">
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
					<Link
						href={SUPPORT_HREF}
						className={cn(ROW, "text-ink-2 hover:bg-surface-2 hover:text-ink")}
					>
						<span className="w-4 shrink-0" />
						{!collapsed && <span>Support</span>}
					</Link>
					<a
						href="/sign-out"
						className={cn(ROW, "text-ink-2 hover:bg-surface-2 hover:text-ink")}
					>
						<span className="w-4 shrink-0" />
						{!collapsed && <span>Sign out</span>}
					</a>
				</div>
			</details>
		</>
	);
}
