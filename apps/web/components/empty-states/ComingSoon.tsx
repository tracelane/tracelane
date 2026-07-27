/**
 * ComingSoon — the honest V1.1 empty-state surface for nav items whose feature
 * ships post-V1 (Datasets, Experiments, Playground). It states plainly what the
 * surface will do and that it is not here yet. NO fabricated UI, no fake data,
 * no entitlement stub — the absence of a category-standard surface reads as a
 * gap in five seconds, so we name it instead of hiding it.
 */

import { EmptyState } from "@tracelanedev/ui";
import type { ReactNode } from "react";

export function ComingSoon({
	title,
	description,
	icon,
}: {
	title: string;
	description: string;
	icon?: ReactNode;
}) {
	return (
		<div className="mx-auto max-w-3xl px-6 py-10">
			<div className="mb-6 flex items-center gap-2">
				<h1 className="text-xl font-semibold text-ink">{title}</h1>
				<span className="rounded border border-line px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-ink-3">
					V1.1
				</span>
			</div>
			<EmptyState
				icon={icon}
				title={`${title} is coming in V1.1`}
				description={description}
			/>
		</div>
	);
}
