"use client";

/**
 * TopBar — the thin strip beside the sidebar (ADR-074 §6). It keeps ONLY three
 * things: environment context, Cmd+K, and notifications. Everything that used to
 * live on the 11-item horizontal bar now lives in the sidebar.
 *
 * CMD+K IS FIRST-CLASS, NOT A NICETY (§6) — it is what keeps the sidebar at nine
 * items, so it is rendered as a real, labelled, always-visible control with its
 * shortcut shown, never a bare icon. The R12 before-inventory found the palette
 * carrying 5 destinations and ZERO unique ones; it has to earn its place before
 * the sidebar can shed anything to it, and hiding it would guarantee it never does.
 *
 * NO BLUR. The old bar used `backdrop-blur-xl`; ADR-074 §5 bans blur outright and
 * §9 lists it as a binding engineering constraint. This is a solid surface.
 */

import { NotificationBell } from "@/components/notifications/NotificationBell";
import type { ReactNode } from "react";
import { ThemeToggle } from "./ThemeToggle";

/**
 * Open the command palette. `CommandPalette` owns a global Cmd+K listener
 * (CommandPalette.tsx:107), so this dispatches the event it already handles rather
 * than lifting state into a context that nothing else needs — one caller, one wire.
 */
function openPalette() {
	window.dispatchEvent(
		new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true }),
	);
}

export function TopBar({ orgSlot }: { orgSlot?: ReactNode }) {
	return (
		<header className="flex h-12 shrink-0 items-center gap-3 border-line border-b bg-canvas px-4">
			<button
				type="button"
				onClick={openPalette}
				aria-label="Search — open the command palette"
				className="flex h-8 min-w-56 items-center gap-2 rounded-md border border-line bg-surface px-2.5 text-ink-3 text-sm transition-colors hover:border-line-2 hover:text-ink-2 max-sm:min-w-0"
			>
				<svg
					viewBox="0 0 16 16"
					width="14"
					height="14"
					fill="none"
					stroke="currentColor"
					strokeWidth="1.6"
					strokeLinecap="round"
					aria-hidden="true"
					className="shrink-0"
				>
					<circle cx="7" cy="7" r="4.5" />
					<path d="m10.5 10.5 3 3" />
				</svg>
				<span className="max-sm:hidden">Search</span>
				<kbd className="ml-auto hidden rounded border border-line bg-canvas-sunken px-1.5 py-0.5 font-mono text-[10px] text-ink-3 sm:inline">
					⌘K
				</kbd>
			</button>

			<div className="ml-auto flex items-center gap-2">
				{orgSlot}
				<NotificationBell />
				<ThemeToggle compact />
			</div>
		</header>
	);
}
