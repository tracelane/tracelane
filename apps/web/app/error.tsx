"use client";

/**
 * Route-segment error boundary — styled fallback for thrown Server/Client
 * Component errors below the root layout. The layout (and its globals.css)
 * still render around this, so Tailwind utilities apply. Pairs with
 * global-error.tsx, which covers failures in the root layout itself.
 */

import { reloadOnChunkError } from "@/lib/chunk-reload";
import { Logo } from "@tracelanedev/ui";
import Link from "next/link";
import { useEffect, useState } from "react";

export default function RouteError({
	error,
	reset,
}: {
	error: Error & { digest?: string };
	reset: () => void;
}) {
	// Version-skew self-heal: a stale client hitting a fresh build throws a
	// chunk-load error — hard-reload once to fetch the new build instead of
	// stranding the user here. Loop-guarded (see chunk-reload.ts).
	const [updating, setUpdating] = useState(false);
	useEffect(() => {
		if (reloadOnChunkError(error)) setUpdating(true);
	}, [error]);

	if (updating) {
		return (
			<div className="min-h-screen bg-bg flex items-center justify-center p-6">
				<p className="text-sm text-ink-2">Updating to the latest version…</p>
			</div>
		);
	}

	return (
		<div className="min-h-screen bg-bg flex items-center justify-center p-6">
			<div className="w-full max-w-md text-center space-y-6">
				<div className="flex justify-center">
					<Logo withWordmark />
				</div>
				<h1 className="t-h1">Something went wrong</h1>
				<p className="text-sm text-ink-2">
					An unexpected error occurred. You can retry, or head back to your
					dashboard.
				</p>
				{error.digest && (
					<p className="text-xs font-mono text-ink-3">
						Reference: {error.digest}
					</p>
				)}
				<div className="flex items-center justify-center gap-3">
					<button
						type="button"
						onClick={reset}
						// `bg-selected text-selected-on` — the theme-stable primary pair. This is a
						// hand-rolled primary CTA (a <Link>/<button>, not the <Button> primitive), and it
						// carried `bg-surface-inverse text-ink-inverse` until the 2026-08-22 contrast
						// audit: in DARK `--surface-inverse` is #0d0e10 — the PAGE GROUND — so the fill
						// sat at 1.00:1 against the canvas and 1.07:1 against a card, leaving a label
						// with no visible button under it. Button.tsx made this exact swap for the
						// primitive; these copies were missed. `--selected` flips per theme: 17.93:1 in
						// light, 17.71:1 in dark, label included.
						className="bg-selected text-selected-on hover:opacity-90 px-4 py-2 rounded-lg text-sm font-medium"
					>
						Try again
					</button>
					<Link
						href="/"
						className="px-4 py-2 rounded-lg text-sm font-medium border border-line text-ink hover:border-ink-3 transition-colors"
					>
						Back to dashboard
					</Link>
				</div>
			</div>
		</div>
	);
}
