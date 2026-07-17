import type { ReactNode } from "react";
import { cn } from "../lib/cn";

export interface EmptyStateProps {
	icon?: ReactNode;
	title: string;
	/** Guide the next action ("send your first trace →"), never a dead end. */
	description?: string;
	action?: ReactNode;
	className?: string;
}

/**
 * Empty state for any surface a user lands on before data. Their absence is the
 * #2 toy tell (after the filter bar) — every surface ships one.
 */
export function EmptyState({
	icon,
	title,
	description,
	action,
	className,
}: EmptyStateProps) {
	return (
		<div
			className={cn(
				"flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-line bg-surface/40 px-6 py-12 text-center",
				className,
			)}
		>
			{icon && (
				<div className="text-ink-3" aria-hidden>
					{icon}
				</div>
			)}
			<div className="space-y-1">
				<p className="text-sm font-medium text-ink">{title}</p>
				{description && (
					<p className="mx-auto max-w-sm text-[13px] text-ink-2">
						{description}
					</p>
				)}
			</div>
			{action}
		</div>
	);
}
