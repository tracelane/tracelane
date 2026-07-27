/**
 * Root 404 — rendered for any unmatched URL and for any `notFound()` call.
 * Lives inside the dashboard shell (the sidebar stays), Neon-styled, and
 * always offers a way out (never a dead end — the design-system spec §4).
 */

import Link from "next/link";

export default function NotFound() {
	return (
		<main className="flex min-h-[70vh] flex-1 items-center justify-center p-6">
			<div className="w-full max-w-md text-center">
				<p className="font-mono text-6xl font-semibold leading-none text-accent-ink">
					404
				</p>
				<h1 className="mt-3 text-xl font-semibold text-ink">
					This page doesn&apos;t exist
				</h1>
				<p className="mt-1.5 text-sm text-ink-2">
					The page you&apos;re looking for moved or never existed. Check the
					URL, or head back to your traces.
				</p>
				<div className="mt-6 flex items-center justify-center">
					<Link
						href="/traces"
						className="cta-lava inline-flex h-9 items-center rounded-lg px-4 text-[13px] font-medium"
					>
						Back to traces
					</Link>
				</div>
			</div>
		</main>
	);
}
