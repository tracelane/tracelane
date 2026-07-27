import type { ReactNode } from "react";
import { cn } from "../lib/cn";

export interface EmptyStateProps {
	icon?: ReactNode;
	title: string;
	/** Guide the next action ("send your first trace →"), never a dead end. */
	description?: string;
	action?: ReactNode;
	/**
	 * Tighter box for in-grid / no-data tiles (e.g. a dashboard card's "No tool
	 * calls yet"). Halves the vertical padding so an empty tile doesn't eat the
	 * frame; full-page first-run states keep the roomy default.
	 */
	compact?: boolean;
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
	compact,
	className,
}: EmptyStateProps) {
	return (
		<div
			className={cn(
				"flex flex-col items-center justify-center rounded-xl border border-dashed border-line bg-surface/40 text-center",
				compact ? "gap-2 px-4 py-6" : "gap-3 px-6 py-12",
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
