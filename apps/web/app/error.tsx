"use client";

/**
 * Route-segment error boundary — styled fallback for thrown Server/Client
 * Component errors below the root layout. The layout (and its globals.css)
 * still render around this, so Tailwind utilities apply. Pairs with
 * global-error.tsx, which covers failures in the root layout itself.
 */

import { Logo } from "@tracelanedev/ui";
import Link from "next/link";

export default function RouteError({
	error,
	reset,
}: {
	error: Error & { digest?: string };
	reset: () => void;
}) {
	return (
		<div className="min-h-screen bg-bg flex items-center justify-center p-6">
			<div className="w-full max-w-md text-center space-y-6">
				<div className="flex justify-center">
					<Logo withWordmark />
				</div>
				<h1 className="text-2xl font-semibold text-ink">
					Something went wrong
				</h1>
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
						className="cta-lava px-4 py-2 rounded-lg text-sm font-medium"
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
