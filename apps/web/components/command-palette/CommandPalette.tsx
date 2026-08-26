"use client";

/**
 * CommandPalette — ⌘K quick navigation.
 *
 * Fuzzy-matches a fixed list of dashboard destinations (Traces, Sessions, SLO,
 * Prompts, BYOK Keys) by label/description and navigates to the
 * chosen one. It does NOT search trace/span content — this is destination
 * navigation, not data search. (Instant trace search by id/model/tenant —
 * PP-O5 — needs a search backend that isn't built yet; tracked as V1.1.)
 * Keyboard: ⌘K / Ctrl+K to open; ArrowUp/Down to navigate; Enter to execute; Esc to close.
 */

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

interface Action {
	id: string;
	label: string;
	description?: string;
	href?: string;
	shortcut?: string;
	group: "navigation" | "action";
}

const STATIC_ACTIONS: Action[] = [
	{
		id: "traces",
		label: "Traces",
		description: "Browse all spans and traces",
		href: "/traces",
		group: "navigation",
	},
	{
		id: "sessions",
		label: "Sessions",
		description: "View agent sessions grouped by run",
		href: "/sessions",
		group: "navigation",
	},
	{
		id: "slo",
		label: "SLO Dashboard",
		description: "Service level objectives and error budgets",
		href: "/slo",
		group: "navigation",
	},
	{
		id: "prompts",
		label: "Prompt Studio",
		description: "Promote and version prompts",
		href: "/prompts",
		group: "navigation",
	},
	{
		id: "byok-keys",
		label: "BYOK Keys",
		description: "Manage customer-managed encryption keys",
		href: "/settings/byok",
		group: "navigation",
	},
];

/**
 * The matched run inside a result label or description.
 *
 * WAS a colour-only highlight — a transparent `<mark>` tinted with `--info-ink`.
 * `--info` used to be blue; the P0 palette retargets it at the chart neutral
 * (#202124 light / #f2f2f2 dark), so the "highlight" became primary ink on
 * primary-ink text and distinguished NOTHING. That is the failure mode a role
 * token has when its value moves: nothing errors, the mark just stops meaning
 * anything.
 *
 * The replacement is a `--surface-3` run at a heavier weight — TWO signals, and
 * neither of them a hue, so it survives a monochrome system and a viewer who
 * cannot resolve a 6% tonal step. `--surface-3` specifically, not `--surface-2`:
 * the SELECTED row is painted `--surface-2`, so a `--surface-2` mark would be
 * invisible on exactly the row the user is looking at. Verified in both themes —
 * on the selected row #ebebe9-on-#f5f5f4 and #26272b-on-#1c1d20; on an unselected
 * row #ebebe9-on-#ffffff and #26272b-on-#151619.
 *
 * The explicit background is also load-bearing: `<mark>` has a UA default of
 * yellow-on-black that no reset in this app clears, which is what the previous
 * transparent value was there for.
 */
function highlight(text: string, query: string): React.ReactNode {
	if (!query) return text;
	const idx = text.toLowerCase().indexOf(query.toLowerCase());
	if (idx === -1) return text;
	return (
		<>
			{text.slice(0, idx)}
			<mark className="bg-surface-3 font-semibold text-ink">
				{text.slice(idx, idx + query.length)}
			</mark>
			{text.slice(idx + query.length)}
		</>
	);
}

export function CommandPalette() {
	const [open, setOpen] = useState(false);
	const [query, setQuery] = useState("");
	const [selectedIndex, setSelectedIndex] = useState(0);
	const inputRef = useRef<HTMLInputElement>(null);
	const listRef = useRef<HTMLUListElement>(null);
	const dialogRef = useRef<HTMLDialogElement>(null);
	const router = useRouter();

	const filtered = STATIC_ACTIONS.filter(
		(a) =>
			!query ||
			a.label.toLowerCase().includes(query.toLowerCase()) ||
			a.description?.toLowerCase().includes(query.toLowerCase()),
	);

	const execute = useCallback(
		(action: Action) => {
			if (action.href) router.push(action.href);
			setOpen(false);
			setQuery("");
			setSelectedIndex(0);
		},
		[router],
	);

	// Global ⌘K / Ctrl+K listener
	useEffect(() => {
		const handler = (e: KeyboardEvent) => {
			if ((e.metaKey || e.ctrlKey) && e.key === "k") {
				e.preventDefault();
				setOpen((prev) => !prev);
			}
		};
		window.addEventListener("keydown", handler);
		return () => window.removeEventListener("keydown", handler);
	}, []);

	// Promote to a REAL modal, and focus the input.
	//
	// This element rendered as `<dialog open>` until 2026-08-18, which is a
	// NON-modal dialog: the page behind it stayed focusable, Tab walked straight
	// out of the palette, and nothing made the rest of the document inert — while
	// the element also carried `aria-modal="true"`, a claim about behaviour it did
	// not have. `showModal()` is what actually buys the top layer, the focus trap
	// and the inert background, so `aria-modal` is now gone as redundant.
	//
	// `showModal()` throws `InvalidStateError` on an already-open dialog (reachable
	// under React 19 StrictMode's double-invoked effects), hence the `.open` check.
	useEffect(() => {
		if (!open) {
			setQuery("");
			return;
		}
		const el = dialogRef.current;
		if (!el) return;
		if (!el.open) el.showModal();
		requestAnimationFrame(() => inputRef.current?.focus());
		setSelectedIndex(0);

		// Escape now arrives as the native `cancel` event. Preventing the default
		// close keeps the browser from closing the dialog behind React's back and
		// leaving `open` true with nothing rendered.
		const onCancel = (e: Event) => {
			e.preventDefault();
			setOpen(false);
		};
		// The dialog fills the viewport and the panel is its child, so a click
		// reported against the dialog itself landed outside the panel. Bound as a
		// native listener rather than an `onClick` prop: `onClick` on a `<dialog>`
		// trips `lint/a11y/useKeyWithClickEvents`, whose only accepted answer is a
		// keyboard handler on the same element — and a decorative `onKeyDown` added
		// to quiet a linter is exactly the kind of claim this repo keeps deleting.
		const onClick = (e: MouseEvent) => {
			if (e.target === el) setOpen(false);
		};

		el.addEventListener("cancel", onCancel);
		el.addEventListener("click", onClick);
		return () => {
			el.removeEventListener("cancel", onCancel);
			el.removeEventListener("click", onClick);
		};
	}, [open]);

	// Scroll selected item into view
	useEffect(() => {
		const list = listRef.current;
		if (!list) return;
		const item = list.children[selectedIndex] as HTMLElement | undefined;
		item?.scrollIntoView({ block: "nearest" });
	}, [selectedIndex]);

	const handleKeyDown = useCallback(
		(e: React.KeyboardEvent) => {
			switch (e.key) {
				case "ArrowDown":
					e.preventDefault();
					setSelectedIndex((i) => Math.min(i + 1, filtered.length - 1));
					break;
				case "ArrowUp":
					e.preventDefault();
					setSelectedIndex((i) => Math.max(i - 1, 0));
					break;
				case "Enter":
					e.preventDefault();
					if (filtered[selectedIndex]) execute(filtered[selectedIndex]);
					break;
			}
		},
		[execute, filtered, selectedIndex],
	);

	const handleQueryChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		setQuery(e.target.value);
		setSelectedIndex(0);
	};

	if (!open) return null;

	return (
		<dialog
			ref={dialogRef}
			aria-label="Command palette"
			className="fixed inset-0 z-50 m-0 flex h-full max-h-none w-full max-w-none items-start justify-center border-none bg-black/60 p-0 pt-[18vh]"
		>
			{/*
			 * Inner panel. No stopPropagation: the dialog's own handler compares
			 * `e.target` against the dialog element, so a click anywhere in here is
			 * already outside the "clicked the scrim" case.
			 *
			 * P0 token pass. Three values were off the system and each is now the
			 * token that names the role:
			 *   · `--surface`, not `--bg`. The panel was painted the PAGE GROUND, so a
			 *     floating overlay used the same material as the thing it floats over —
			 *     flat in light, and in dark the panel (#0d0e10) was DARKER than the
			 *     cards behind it. `--surface` is lighter than the ground in both
			 *     themes, which is what "in front" means here.
			 *   · `--radius-card`, not Tailwind's 16px `rounded-2xl`. The system has two
			 *     radii; a panel takes the card one.
			 *   · `--shadow-overlay`, not Tailwind's heaviest stock drop. The overlay
			 *     elevation is defined once, in both themes, and a default-scale shadow
			 *     is a fourth elevation nobody declared. The class it replaced is
			 *     DESCRIBED rather than quoted: Tailwind extracts candidates from raw
			 *     file bytes, comments included, so naming it here would keep emitting
			 *     its rule into the built sheet with no element wearing it (the trap
			 *     `NavProgress.tsx` records) — and it now has zero real call sites.
			 *
			 * It stays SOLID rather than taking the translucent chrome class. Glass is
			 * sanctioned for overlays, but this one sits on a 60%-black scrim: the blur
			 * would sample the scrim, so it pays a per-frame compositor pass to blur a
			 * flat dim. Nothing to see through is not a case for see-through.
			 */}
			<div
				role="presentation"
				className="w-full max-w-xl overflow-hidden rounded-[var(--radius-card)] border border-line bg-surface shadow-[var(--shadow-overlay)]"
				onKeyDown={handleKeyDown}
			>
				{/* Input row */}
				<div className="flex items-center gap-3 border-b border-line px-4 py-3">
					<svg
						aria-hidden="true"
						focusable="false"
						className="h-4 w-4 shrink-0 text-ink-2"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
						/>
					</svg>
					<input
						ref={inputRef}
						className="flex-1 bg-transparent text-sm text-ink placeholder:text-ink-3"
						placeholder="Jump to a page…"
						value={query}
						onChange={handleQueryChange}
						aria-label="Search"
						aria-autocomplete="list"
						aria-activedescendant={
							filtered[selectedIndex]
								? `cmd-item-${filtered[selectedIndex].id}`
								: undefined
						}
					/>
					{/* `--canvas-sunken`, matching the TopBar's ⌘K key: one <kbd> material
					    for the app, and it is the only surface token that reads as
					    RECESSED against a card in both themes. */}
					<kbd className="shrink-0 rounded border border-line bg-canvas-sunken px-1.5 py-0.5 font-mono text-2xs font-medium text-ink-2">
						ESC
					</kbd>
				</div>

				{/* Results */}
				<ul
					ref={listRef}
					aria-label="Actions"
					className="max-h-72 overflow-y-auto py-2"
				>
					{filtered.length === 0 && (
						<li className="px-4 py-6 text-center text-xs text-ink-2">
							No results for &ldquo;{query}&rdquo;
						</li>
					)}
					{filtered.map((action, idx) => (
						<li
							key={action.id}
							id={`cmd-item-${action.id}`}
							aria-selected={idx === selectedIndex}
							/*
							 * SELECTED is the only row state, and the hover class that used
							 * to sit on the idle branch is DELETED rather than retoned.
							 * `onMouseEnter` promotes the row to selected, so hovering and
							 * selecting are the same event here: the hover fill could only
							 * ever paint for the single frame before React re-rendered, and
							 * on a keyboard-driven palette it never painted at all. It was
							 * also `--surface`, which is now the panel's own colour — a
							 * hover that changes nothing.
							 */
							className={`mx-2 flex cursor-pointer items-center gap-3 rounded-[var(--radius-control)] px-3 py-2.5 text-sm transition-colors ${
								idx === selectedIndex ? "bg-surface-2 text-ink" : "text-ink"
							}`}
							onClick={() => execute(action)}
							onKeyDown={(e) => {
								if (e.key === "Enter" || e.key === " ") {
									e.preventDefault();
									execute(action);
								}
							}}
							onMouseEnter={() => setSelectedIndex(idx)}
						>
							<div className="min-w-0 flex-1">
								<p className="truncate font-medium">
									{highlight(action.label, query)}
								</p>
								{action.description && (
									<p className="truncate text-xs text-ink-2">
										{highlight(action.description, query)}
									</p>
								)}
							</div>
							<svg
								aria-hidden="true"
								focusable="false"
								className="h-3.5 w-3.5 shrink-0 text-ink-3"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M9 5l7 7-7 7"
								/>
							</svg>
						</li>
					))}
				</ul>

				{/* Footer hint */}
				{/* Footer hint keys take the same `--canvas-sunken` material as the two
				    above, so the palette does not carry three kinds of <kbd>. */}
				<div className="flex items-center gap-4 border-t border-line px-4 py-2 text-2xs text-ink-3">
					<span>
						<kbd className="rounded border border-line bg-canvas-sunken px-1 font-mono">
							↑↓
						</kbd>{" "}
						navigate
					</span>
					<span>
						<kbd className="rounded border border-line bg-canvas-sunken px-1 font-mono">
							↵
						</kbd>{" "}
						open
					</span>
					<span>
						<kbd className="rounded border border-line bg-canvas-sunken px-1 font-mono">
							esc
						</kbd>{" "}
						close
					</span>
				</div>
			</div>
		</dialog>
	);
}
