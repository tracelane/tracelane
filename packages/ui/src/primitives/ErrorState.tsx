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
				"flex flex-col items-center justify-center gap-3 rounded-xl border border-danger/30 bg-danger-soft/40 px-6 py-10 text-center",
				className,
			)}
		>
			<div className="space-y-1">
				<p className="text-sm font-medium text-ink">{title}</p>
				<p className="mx-auto max-w-sm text-[13px] text-ink-2">{description}</p>
			</div>
			{action}
		</div>
	);
}
