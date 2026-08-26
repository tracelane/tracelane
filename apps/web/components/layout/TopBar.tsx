"use client";

/**
 * TopBar — the thin strip beside the sidebar (ADR-074 §6). It keeps ONLY three
 * things: environment context, Cmd+K, and notifications. Everything that used to
 * live on the 11-item horizontal bar now lives in the sidebar.
 *
 * NO TOP NAVIGATION. Navigation is the rail's job; this bar carries no
 * destinations, and adding one here would re-create the horizontal bar §6 deleted.
 *
 * CMD+K IS FIRST-CLASS, NOT A NICETY (§6) — it is what keeps the sidebar at nine
 * items, so it is rendered as a real, labelled, always-visible control with its
 * shortcut shown, never a bare icon. The R12 before-inventory found the palette
 * carrying 5 destinations and ZERO unique ones; it has to earn its place before
 * the sidebar can shed anything to it, and hiding it would guarantee it never does.
 *
 * ── P0.14 (2026-08-22) ───────────────────────────────────────────────────────
 * THE BAR KEEPS `.glass`, AND THIS IS THE PLACE IN THE CHROME THAT EARNS IT. The
 * bar is `sticky` INSIDE the scrolling content column, so page content genuinely
 * travels under it — the one case tokens.css sanctions the translucent material
 * for. The rail went solid in the same pass for the opposite reason: nothing ever
 * passes beneath a full-height column beside the content. Same rule, two answers,
 * because the rule is about what is behind the surface.
 *
 * (The old header comment here said "NO BLUR … this is a solid surface", which had
 * been false since the class was applied: `.glass` IS a `backdrop-filter`. It is
 * rewritten rather than deleted because a comment contradicting the code beneath
 * it is a defect in this repo, CLAUDE.md §17.)
 *
 * HEIGHT: `h-14` rather than `h-12`. The search control grew to `h-9` so it reads
 * as a real field instead of a chip, and a 36px control in a 48px bar leaves 6px
 * of air on each side — visually pinched. Everything here is rem, so the bar
 * tracks the adaptive root like the rest of the app.
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
		<header className="glass sticky top-0 z-40 flex h-14 shrink-0 items-center gap-3 border-b border-line px-4">
			{/*
			 * The command surface. `--surface` (the card white / #151619), NOT the
			 * `--surface-2` well, and the deciding reason is the ⌘K key inside it:
			 * the key is painted `--canvas-sunken`, which reads as RECESSED against
			 * the card in both themes (#f1f1f0 under #ffffff; #0a0a0c under #151619).
			 * Against a `--surface-2` field it would be #f1f1f0 on #f5f5f4 in light —
			 * four values apart, i.e. gone. A field whose own affordance disappears in
			 * one theme is not the calmer choice, it is the one nobody checked.
			 *
			 * Placeholder-weight text is `--ink-3` (the UI floor) and lifts to
			 * secondary ink on hover, so the control is quiet at rest and answers when
			 * approached.
			 */}
			<button
				type="button"
				onClick={openPalette}
				aria-label="Search — open the command palette"
				className="flex h-9 min-w-64 items-center gap-2.5 rounded-[var(--radius-control)] border border-line bg-surface px-3 text-ink-3 text-sm transition-colors hover:border-line-2 hover:text-ink-2 max-sm:min-w-0"
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
				<kbd className="ml-auto hidden rounded border border-line bg-canvas-sunken px-1.5 py-0.5 font-mono text-2xs text-ink-3 sm:inline">
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
