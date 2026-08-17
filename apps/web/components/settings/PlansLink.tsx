/**
 * PlansLink — the "compare all plans" affordance on /settings/billing (SET-15).
 *
 * It used to be an external anchor to `tracelane.dev/#pricing`, which meant the
 * product's own plan comparison lived on the marketing site: a customer had to
 * leave the dashboard, and the figures they read were bound by no code check.
 * It now points at `/plans`, the in-app ladder derived from the entitlement map.
 *
 * A component rather than a bare `<a>` so the destination is one rendered thing
 * a test can assert — the regression this closes is precisely "the link points
 * off-product again".
 */

import Link from "next/link";

export function PlansLink({ className }: { className?: string }) {
	return (
		<Link
			href="/plans"
			data-testid="plans-link"
			className={
				className ??
				"inline-block text-xs text-ink-2 underline underline-offset-2 transition-colors hover:text-ink"
			}
		>
			Compare all plans →
		</Link>
	);
}
