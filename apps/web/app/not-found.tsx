/**
 * Root 404 — rendered for any unmatched URL and for any `notFound()` call.
 * Lives inside the dashboard shell (the sidebar stays) and always offers a way
 * out (never a dead end — the design-system spec §4).
 *
 * "Neon-styled" used to appear on the line above. That was the name of a design
 * language two palettes ago; nothing in this file has been Neon-styled for a
 * long time and the word only sent a reader looking for a system that no longer
 * exists (CLAUDE.md §17).
 */

import Link from "next/link";

export default function NotFound() {
	return (
		<div className="flex min-h-[70vh] flex-1 items-center justify-center p-6">
			<div className="w-full max-w-md text-center">
				{/* `--ink-3`, not `--action-ink`. The numeral is decoration — not an
				    action and not a datum — so under "colour is data" it takes the
				    quietest tone in the ramp and the sentence beneath it leads. */}
				<p className="font-mono text-6xl font-semibold leading-none text-ink-3">
					404
				</p>
				<h1 className="t-h1 mt-3">This page doesn&apos;t exist</h1>
				<p className="mt-1.5 text-sm text-ink-2">
					The page you&apos;re looking for moved or never existed. Check the
					URL, or head back to your traces.
				</p>
				<div className="mt-6 flex items-center justify-center">
					<Link
						href="/traces"
						// `bg-selected text-selected-on` — the theme-stable primary pair. This is a
						// hand-rolled primary CTA (a <Link>/<button>, not the <Button> primitive), and it
						// carried `bg-surface-inverse text-ink-inverse` until the 2026-08-22 contrast
						// audit: in DARK `--surface-inverse` is #0d0e10 — the PAGE GROUND — so the fill
						// sat at 1.00:1 against the canvas and 1.07:1 against a card, leaving a label
						// with no visible button under it. Button.tsx made this exact swap for the
						// primitive; these copies were missed. `--selected` flips per theme: 17.93:1 in
						// light, 17.71:1 in dark, label included.
						className="bg-selected text-selected-on hover:opacity-90 inline-flex h-9 items-center rounded-lg px-4 text-sm font-medium"
					>
						Back to traces
					</Link>
				</div>
			</div>
		</div>
	);
}
