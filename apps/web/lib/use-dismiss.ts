"use client";

/**
 * `useDismiss` — Escape and click-outside for a NON-modal popover.
 *
 * A modal gets both from the platform via `<dialog>.showModal()` and should use
 * `components/Modal.tsx` instead. A popover is deliberately not modal — the page
 * behind it stays live — so nothing hands it these two behaviours, and every
 * popover in this app was missing both:
 *
 *   - `NotificationBell` opened a panel that only the bell itself could close.
 *     Escape did nothing and clicking the page left it hanging over the content.
 *   - `AccountMenu` used `<details>/<summary>` under a comment asserting it "gets
 *     keyboard support, Escape, and click-outside-to-close from the platform".
 *     `<details>` gives keyboard toggling and NOTHING ELSE — no Escape, no
 *     click-outside. The comment was the only place either behaviour existed.
 *
 * Attach the returned ref to the element that encloses BOTH the trigger and the
 * panel, so clicking the trigger to close does not read as an outside click and
 * immediately re-open.
 *
 * `pointerdown`, not `click`: a `click` listener fires after React has already
 * processed the press, which lets a link inside the panel navigate and *then*
 * close — and it misses a drag that starts outside. `keydown` is captured on the
 * document so Escape works even when focus never entered the panel.
 */

import { type RefObject, useEffect, useRef } from "react";

export function useDismiss<T extends HTMLElement>(
	open: boolean,
	onDismiss: () => void,
): RefObject<T | null> {
	const ref = useRef<T>(null);

	// The callback is read through a ref so an inline arrow at the call site does
	// not re-subscribe the document listeners on every render.
	const cb = useRef(onDismiss);
	cb.current = onDismiss;

	useEffect(() => {
		if (!open) return;

		const onPointerDown = (e: PointerEvent) => {
			const el = ref.current;
			if (el && e.target instanceof Node && !el.contains(e.target)) {
				cb.current();
			}
		};
		const onKeyDown = (e: KeyboardEvent) => {
			if (e.key === "Escape") cb.current();
		};

		document.addEventListener("pointerdown", onPointerDown);
		document.addEventListener("keydown", onKeyDown);
		return () => {
			document.removeEventListener("pointerdown", onPointerDown);
			document.removeEventListener("keydown", onKeyDown);
		};
	}, [open]);

	return ref;
}
