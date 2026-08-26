"use client";

/**
 * Modal — the ONE modal shell for the app, built on the native `<dialog>` element
 * driven by `showModal()`.
 *
 * **Why the platform and not a hand-rolled div.** Every modal in this app was a
 * `<div className="fixed inset-0 …">` with a nested panel div. That shape gives a
 * screen reader no dialog role, no accessible name, and no modal boundary; it
 * leaves the page behind the scrim fully focusable, so Tab walks out of the
 * dialog into content the user cannot see; and Escape does nothing. Eight of them
 * shipped that way, and two of the eight gate **API-key minting** and **BYOK CMK
 * rotation** — the two surfaces in the product where tabbing into a control you
 * cannot see costs a credential.
 *
 * `dialog.showModal()` supplies all four from the platform, with no focus-trap
 * library and no `aria-modal` claim to keep true:
 *   - implicit `role="dialog"` **and** modal semantics (top layer);
 *   - the rest of the document becomes inert — focus cannot leave, Tab wraps;
 *   - Escape fires `cancel`, then `close`;
 *   - the top layer sits above every `z-index` on the page, because it is not
 *     part of the page's stacking context at all.
 *
 * `aria-modal="true"` is deliberately NOT set. On a `showModal()` dialog it is
 * redundant. The one place this app did set it — the command palette — set it on
 * a `<dialog open>`, which is a NON-modal dialog: the attribute was a false claim
 * about behaviour the element did not have.
 *
 * **The dialog fills the viewport and centers its panel with flex, rather than
 * relying on the UA's `margin: auto`.** Tailwind v4's preflight applies
 * `margin: 0` to `*` (`preflight.css:7-15`), which silently defeats the centering
 * every `<dialog>` tutorial assumes — the same shape as the `outline-none` /
 * `focus-visible:outline-2` defect that made 22 focus rings invisible. Nothing
 * here depends on a UA default a reset can take away. For the same reason the
 * scrim is painted on the dialog's own background rather than `::backdrop`: the
 * dialog covers the viewport, so the backdrop pseudo-element is never seen.
 *
 * **Accessible name.** `title` renders as the `<h2>` and is wired to the dialog
 * through `aria-labelledby`. A modal without a name announces as "dialog", which
 * tells the user a box appeared and nothing about what it wants.
 *
 * **`dismissable={false}`** keeps Escape and backdrop-click from closing — for the
 * one dialog that shows a secret exactly once (`ApiKeyManager`'s reveal). A stray
 * Escape there destroys a credential the server cannot re-issue.
 */

import { useEffect, useId, useRef } from "react";

export function Modal({
	onClose,
	title,
	description,
	titleAside,
	children,
	width = "md",
	dismissable = true,
}: {
	/** Called on Escape and on backdrop click. Owns the unmount. */
	onClose: () => void;
	/** Accessible name. Rendered as the heading and wired via aria-labelledby. */
	title: string;
	/**
	 * Sub-heading, rendered tight under the title (not as a body row).
	 * A caption that belongs to the heading — "which key was just created" — is
	 * unreadable 16px below it in the body's own vertical rhythm.
	 */
	description?: React.ReactNode;
	/** Optional node on the title row, right-aligned (e.g. a "shown once" badge). */
	titleAside?: React.ReactNode;
	children: React.ReactNode;
	width?: "md" | "lg";
	dismissable?: boolean;
}) {
	const ref = useRef<HTMLDialogElement>(null);
	const titleId = useId();

	// Behaviour is bound with NATIVE listeners rather than React props, for one
	// reason worth stating: `onClick` on a `<dialog>` trips
	// `lint/a11y/useKeyWithClickEvents`, whose only accepted answer is a keyboard
	// handler on the same element. Adding a decorative `onKeyDown` to satisfy a
	// linter — when Escape is already handled properly by `cancel` — is how a
	// suppression comment ends up asserting something untrue. The backdrop is a
	// surface, not a control; it has no keyboard equivalent, and saying so by
	// staying out of the JSX a11y surface is more honest than an ignore comment.
	//
	// The callbacks are read through a ref so this effect subscribes exactly once
	// and never re-runs — re-running it would call `showModal()` again.
	const latest = useRef({ onClose, dismissable });
	latest.current = { onClose, dismissable };

	useEffect(() => {
		const el = ref.current;
		if (!el) return;

		// `showModal()` throws `InvalidStateError` if the dialog is already open —
		// reachable under React 19 StrictMode's double-invoked effects.
		if (!el.open) el.showModal();

		// Escape arrives as `cancel`. `preventDefault` runs unconditionally so the
		// browser can never close the dialog behind React's back and leave the
		// parent still rendering it; it also covers the browser close gestures that
		// are not keydown events.
		const onCancel = (e: Event) => {
			e.preventDefault();
			if (latest.current.dismissable) latest.current.onClose();
		};
		// The dialog fills the viewport and the panel is its child, so a click
		// reported against the dialog itself landed outside the panel.
		const onClick = (e: MouseEvent) => {
			if (latest.current.dismissable && e.target === el)
				latest.current.onClose();
		};

		el.addEventListener("cancel", onCancel);
		el.addEventListener("click", onClick);
		return () => {
			el.removeEventListener("cancel", onCancel);
			el.removeEventListener("click", onClick);
		};
	}, []);

	return (
		<dialog
			ref={ref}
			aria-labelledby={titleId}
			className="fixed inset-0 m-0 flex h-full max-h-none w-full max-w-none items-center justify-center overflow-y-auto bg-black/60 p-4 text-ink"
		>
			{/*
			 * `--radius-card` + `--shadow-overlay`, both by token.
			 *
			 * The comment here used to justify a hand-picked 12px radius on the
			 * grounds that "the card token carries 8px" — true under ADR-074, and
			 * false since the P0 pass: `--radius-card` is 1.125rem (16–20px across
			 * the adaptive root), which IS the large-container band this panel wanted.
			 * The reason for the exception no longer exists, so the exception goes and
			 * the panel takes the system radius.
			 *
			 * The shadow moves off Tailwind's default scale for the same reason: the
			 * overlay elevation is defined once, per theme, in tokens.css. It is still
			 * NOT `.surface-card` — that class paints the card ELEVATION, and a modal
			 * sitting on a scrim is a layer above the cards, not another one of them.
			 */}
			<div
				className={[
					"w-full space-y-4 rounded-[var(--radius-card)] border border-line bg-surface p-6 shadow-[var(--shadow-overlay)]",
					width === "lg" ? "max-w-lg" : "max-w-md",
				].join(" ")}
			>
				<div className="flex items-start justify-between gap-3">
					<div className="min-w-0">
						{/* `text-md` (16px) — the named ramp step. `text-base` was Tailwind's
					    own 1rem: the same rendered size, off the app's scale, so a ramp
					    tweak would have missed it. */}
						<h2 id={titleId} className="font-semibold text-ink text-md">
							{title}
						</h2>
						{description && (
							<p className="mt-0.5 text-xs text-ink-2">{description}</p>
						)}
					</div>
					{titleAside}
				</div>
				{children}
			</div>
		</dialog>
	);
}
