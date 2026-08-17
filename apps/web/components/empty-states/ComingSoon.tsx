/**
 * Unavailable-surface empty state — rendered by `/datasets`, `/experiments` and
 * `/playground`. Tracelane has no feature behind any of those routes: the pages
 * exist only so a direct URL does not 404, and none of them is linked from the
 * nav (`components/layout/nav-config.tsx`).
 *
 * It says exactly that, and nothing more. NO fabricated UI, no fake data, no
 * entitlement stub, and no forward-looking promise — the absence of a
 * category-standard surface reads as a gap in five seconds, so we name it
 * instead of hiding it.
 *
 * `description` is still accepted because the three call sites pass one, but it
 * is deliberately NOT rendered: each of those descriptions narrated a surface
 * that does not exist.
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
			<h1 className="mb-6 text-xl font-semibold text-ink">{title}</h1>
			<EmptyState
				icon={icon}
				title={`Tracelane has no ${title} feature`}
				description="There is nothing behind this page — nothing is recorded, stored or run here."
			/>
		</div>
	);
}
