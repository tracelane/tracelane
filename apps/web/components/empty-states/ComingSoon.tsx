/**
 * Unavailable-surface empty state — rendered by `/datasets`. Tracelane has no
 * feature behind that route: the page exists only so a direct URL does not
 * 404, and it is not linked from the nav (`components/layout/nav-config.tsx`).
 *
 * `/experiments` (EVL-02, 2026-08-24) and `/playground` (OBS-16, 2026-09-06)
 * both moved off this component once a real feature landed behind them — this
 * comment named all three for weeks after the first move, which is exactly
 * the §17 defect (a comment that misdescribes the code it sits next to).
 *
 * It says exactly that, and nothing more. NO fabricated UI, no fake data, no
 * entitlement stub, and no forward-looking promise — the absence of a
 * category-standard surface reads as a gap in five seconds, so we name it
 * instead of hiding it.
 *
 * `description` is still accepted because the remaining call site passes one,
 * but it is deliberately NOT rendered: it narrated a surface that does not
 * exist.
 */

import { EmptyState } from "@tracelanedev/ui";
import type { ReactNode } from "react";

export function ComingSoon({
	title,
	icon,
}: {
	title: string;
	description?: string;
	icon?: ReactNode;
}) {
	return (
		<div className="mx-auto max-w-3xl px-6 py-10">
			<h1 className="t-h1 mb-6">{title}</h1>
			<EmptyState
				icon={icon}
				title={`Tracelane has no ${title} feature`}
				description="There is nothing behind this page — nothing is recorded, stored or run here."
			/>
		</div>
	);
}
