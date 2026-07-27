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
		description: "Promote, version, and evaluate prompts",
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

function highlight(text: string, query: string): React.ReactNode {
	if (!query) return text;
	const idx = text.toLowerCase().indexOf(query.toLowerCase());
	if (idx === -1) return text;
	return (
		<>
			{text.slice(0, idx)}
			<mark className="bg-transparent text-info font-medium">
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

	// Focus input when opened
	useEffect(() => {
		if (open) {
			requestAnimationFrame(() => inputRef.current?.focus());
			setSelectedIndex(0);
		} else {
			setQuery("");
		}
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
				case "Escape":
					setOpen(false);
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
		// eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions
		<dialog
			aria-label="Command palette"
			aria-modal="true"
			className="fixed inset-0 z-50 m-0 flex h-full max-h-none w-full max-w-none items-start justify-center border-none bg-black/60 p-0 pt-[18vh] backdrop-blur-sm"
			onClick={() => setOpen(false)}
			onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
			open
		>
			{/* Inner panel — stop propagation so clicks inside don't close */}
			<div
				role="presentation"
				className="w-full max-w-xl overflow-hidden rounded-2xl border border-line bg-bg shadow-2xl"
				onClick={(e) => e.stopPropagation()}
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
						className="flex-1 bg-transparent text-sm text-ink placeholder:text-ink-2 outline-none"
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
					<kbd className="shrink-0 rounded border border-line bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-ink-2">
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
							className={`mx-2 flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${
								idx === selectedIndex
									? "bg-surface-2 text-ink"
									: "text-ink hover:bg-surface"
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
				<div className="flex items-center gap-4 border-t border-line px-4 py-2 text-[10px] text-ink-3">
					<span>
						<kbd className="rounded border border-line px-1">↑↓</kbd> navigate
					</span>
					<span>
						<kbd className="rounded border border-line px-1">↵</kbd> open
					</span>
					<span>
						<kbd className="rounded border border-line px-1">esc</kbd> close
					</span>
				</div>
			</div>
		</dialog>
	);
}
