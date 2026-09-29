"use client";

/**
 * Coordinates sibling header popovers (item 8: TraceFlag's edit panel and
 * ShareDialog) so opening one closes the other. Neither owns the other's
 * state — they are independent client components mounted as siblings in the
 * trace page header — so this is a tiny broadcast, not a shared store. No
 * new dependency: a `CustomEvent` on `window` is the native primitive for
 * exactly this ("something happened, anyone else listening can react"),
 * which is smaller than reaching for a context provider or a state library
 * this app deliberately does not carry (no Zustand — `apps/web/CLAUDE.md`).
 */

const EVENT = "tracelane:popover-open";

/** Call when a popover OPENS, with its own stable id. */
export function announcePopoverOpen(id: string): void {
	if (typeof window === "undefined") return;
	window.dispatchEvent(new CustomEvent<string>(EVENT, { detail: id }));
}

/** Call when a popover CLOSES, so another popover can close it in turn. */
export function onOtherPopoverOpen(id: string, close: () => void): () => void {
	if (typeof window === "undefined") return () => {};
	function handler(e: Event): void {
		const detail = (e as CustomEvent<string>).detail;
		if (detail !== id) close();
	}
	window.addEventListener(EVENT, handler);
	return () => window.removeEventListener(EVENT, handler);
}
