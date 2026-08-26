import type { ReactNode } from "react";
import { cn } from "../lib/cn";

export interface ErrorStateProps {
	title?: string;
	/**
	 * Action-oriented copy that guides the exit, never blame:
	 * "Your API key is incorrect or expired. Generate a new one in Settings."
	 * — never "Invalid API key." (the design-system spec §4.)
	 */
	description: string;
	action?: ReactNode;
	className?: string;
}

/**
 * TOKEN AUDIT, 2026-08-22 (P0). What was checked and what moved:
 *  · No hardcoded hex, no blue/violet — every colour here is a `--danger` role.
 *    `border-danger/30` and `bg-danger-soft/40` are live tokens with alpha, not
 *    literals, and they stay: the block needs an edge, and there is no
 *    `--danger-line` role to name instead.
 *  · RADIUS FIXED. It was `rounded-xl` (12px), which is neither of the two radii
 *    the system defines — `--radius-card` 18px for cards/tiles/PANELS and
 *    `--radius-control` 8px for controls. A 12px panel is a third radius nobody
 *    declared, and three radii is how a surface stops reading as one system. An
 *    error block is a panel, so it takes the card radius, and it now tracks the
 *    adaptive root the way every other panel does.
 * `role="alert"` and the action-oriented copy contract below are unchanged.
 */
export function ErrorState({
	title = "Something needs attention",
	description,
	action,
	className,
}: ErrorStateProps) {
	return (
		<div
			role="alert"
			className={cn(
				"flex flex-col items-center justify-center gap-3 rounded-[var(--radius-card)] border border-danger/30 bg-danger-soft/40 px-6 py-10 text-center",
				className,
			)}
		>
			<div className="space-y-1">
				<p className="text-sm font-medium text-ink">{title}</p>
				<p className="mx-auto max-w-sm text-sm text-ink-2">{description}</p>
			</div>
			{action}
		</div>
	);
}
