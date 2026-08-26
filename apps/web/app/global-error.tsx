"use client";

/**
 * Global error boundary — last resort when the root layout itself throws.
 * It replaces the entire document, so it must render its own <html>/<body>,
 * and globals.css is NOT guaranteed to be present. Styles are therefore
 * inline so the page stays branded even with no stylesheet (the exact failure
 * mode where a thrown Server Component previously rendered raw, unstyled HTML).
 */

import { reloadOnChunkError } from "@/lib/chunk-reload";
import { useEffect, useState } from "react";

/**
 * THE ONLY LITERAL COLOURS IN THE APPLICATION, AND THE REASON IS STRUCTURAL.
 *
 * `apps/web/CLAUDE.md` is "design tokens only — never hardcode hex", and
 * `scripts/ci/check-design-constraints.py` enforces it as of 2026-08-22. This
 * file is the one genuine exception in the tree: it REPLACES the document after
 * the root layout has thrown, so the stylesheet that defines `--ink` may never
 * have loaded. `var(--ink)` would then resolve to nothing and the page would
 * render as unstyled HTML — or worse, black on black — at exactly the moment a
 * user most needs it to be legible. That is the failure this whole file exists
 * to prevent, so the values have to be literal.
 *
 * WHAT CHANGED, 2026-08-22: they were a zinc ramp (#09090b / #fafafa / #a1a1aa /
 * #52525b / #18181b) left over from an earlier palette, i.e. a set of colours
 * that had quietly stopped matching the product. They are re-synced to the
 * P0 DARK theme, and each is annotated with the token it mirrors. Dark, not
 * light, because this page cannot read the theme cookie's effect — a dark
 * last-resort screen is correct in both, where a white one flashes.
 *
 * NAMED CONSTANTS, NOT INLINE LITERALS, and that is what makes the exemption
 * honest. The values were scattered across twelve JSX sites — twelve places to
 * forget one, and no single place to check the set. Five named constants put the
 * whole exemption in one block a reviewer can read in five seconds, and the next
 * palette swap has one place to update.
 *
 * Each line still carries its own `design-constraint-ok:` marker rather than one
 * for the block. That is the guard's rule, and it is the right rule: a file-level
 * opt-out is how an exemption written for five lines silently grows to cover a
 * sixth that nobody justified.
 */
const C = {
	bg: "#0d0e10", // = --bg (dark) · design-constraint-ok: this file replaces the document when the stylesheet may be absent, so a CSS var resolves to nothing exactly when it is needed — see the block comment above
	ink: "#f5f5f5", // = --ink (dark) · design-constraint-ok: this file replaces the document when the stylesheet may be absent, so a CSS var resolves to nothing exactly when it is needed — see the block comment above
	ink2: "#a1a1aa", // = --ink-2 (dark) · design-constraint-ok: this file replaces the document when the stylesheet may be absent, so a CSS var resolves to nothing exactly when it is needed — see the block comment above
	ink3: "#71717a", // = --ink-3 (dark) · design-constraint-ok: this file replaces the document when the stylesheet may be absent, so a CSS var resolves to nothing exactly when it is needed — see the block comment above
	onInk: "#0d0e10", // = --action-on (dark), the label ON the solid ink button · design-constraint-ok: this file replaces the document when the stylesheet may be absent, so a CSS var resolves to nothing exactly when it is needed — see the block comment above
} as const;

export default function GlobalError({
	error,
	reset,
}: {
	error: Error & { digest?: string };
	reset: () => void;
}) {
	// Version-skew self-heal (see chunk-reload.ts): a stale client on a fresh
	// build throws a chunk-load error — reload once rather than strand the user.
	const [updating, setUpdating] = useState(false);
	useEffect(() => {
		if (reloadOnChunkError(error)) setUpdating(true);
	}, [error]);

	return (
		<html lang="en">
			<body
				style={{
					margin: 0,
					minHeight: "100vh",
					display: "flex",
					alignItems: "center",
					justifyContent: "center",
					background: C.bg,
					color: C.ink,
					fontFamily:
						"ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
				}}
			>
				{updating ? (
					<div style={{ fontSize: "0.875rem", color: C.ink2 }}>
						Updating to the latest version…
					</div>
				) : (
					<div
						style={{
							maxWidth: "28rem",
							textAlign: "center",
							padding: "1.5rem",
						}}
					>
						{/* Inline Chisel mark — self-contained (no CSS vars), since this
					    last-resort page can render with no stylesheet present. */}
						<div
							style={{
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
								gap: "0.5rem",
							}}
						>
							<svg
								viewBox="0 0 100 100"
								width={24}
								height={24}
								fill="none"
								role="img"
								aria-label="Tracelane"
							>
								<path d="M 2,2 L 96,2 L 84,14 L 2,14 Z" fill={C.ink} />
								<path
									d="M 2,14 L 14,14 L 14,28 L 44,28 L 44,40 L 12,40 L 2,30 Z"
									fill={C.ink}
								/>
								<path d="M 32,40 L 44,40 L 44,86 L 32,98 Z" fill={C.ink} />
								<path
									d="M 96,16 L 96,28 L 84,40 L 54,40 L 54,28 L 84,28 Z"
									fill={C.ink}
								/>
								<path
									d="M 54,40 L 66,40 L 66,64 L 78,64 L 54,88 Z"
									fill={C.ink}
								/>
							</svg>
							<span
								style={{
									fontFamily: "ui-monospace, monospace",
									fontSize: "0.9rem",
									fontWeight: 600,
									letterSpacing: "-0.01em",
								}}
							>
								tracelane
							</span>
						</div>
						<h1
							style={{
								fontSize: "1.5rem",
								fontWeight: 600,
								margin: "1rem 0 0.5rem",
							}}
						>
							Something went wrong
						</h1>
						<p
							style={{
								fontSize: "0.875rem",
								color: C.ink2,
								marginBottom: "1.5rem",
							}}
						>
							A critical error occurred while loading the app.
						</p>
						{error.digest && (
							<p
								style={{
									fontSize: "0.75rem",
									fontFamily: "ui-monospace, monospace",
									color: C.ink3,
									marginBottom: "1rem",
								}}
							>
								Reference: {error.digest}
							</p>
						)}
						<button
							type="button"
							onClick={reset}
							style={{
								padding: "0.5rem 1rem",
								borderRadius: "0.5rem",
								border: "none",
								fontSize: "0.875rem",
								fontWeight: 500,
								background: C.ink,
								color: C.onInk,
								cursor: "pointer",
							}}
						>
							Try again
						</button>
					</div>
				)}
			</body>
		</html>
	);
}
