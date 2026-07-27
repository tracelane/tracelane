"use client";

import { Button, ErrorState } from "@tracelanedev/ui";

/**
 * Shared segment error boundary UI. Renders a scoped {@link ErrorState} (the nav
 * shell stays) with a retry that calls Next's `reset()`. Used by the
 * gateway/ClickHouse-backed data surfaces (traces / slo / audit) so a backend
 * failure degrades that view alone instead of escalating to the whole-app root
 * boundary (`app/error.tsx`).
 *
 * Copy guides the exit, never blames (the design-system spec §4); the error is not
 * logged to the console here (CLAUDE.md) — the server already captured the throw.
 */
export function SegmentError({
	reset,
}: {
	error: Error & { digest?: string };
	reset: () => void;
}) {
	return (
		<main className="p-6">
			<ErrorState
				title="This view hit an error"
				description="We couldn't load this data. It's usually transient — retry, and if it persists the gateway or trace store may be unavailable."
				action={
					<Button variant="secondary" onClick={() => reset()}>
						Retry
					</Button>
				}
			/>
		</main>
	);
}
