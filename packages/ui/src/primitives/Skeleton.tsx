import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

/** Loading placeholder. Use skeletons, not spinners-only (the design-system spec §0.5). */
export function Skeleton({
	className,
	...props
}: HTMLAttributes<HTMLDivElement>) {
	return (
		<div
			aria-hidden
			className={cn("animate-pulse rounded-md bg-surface-2", className)}
			{...props}
		/>
	);
}
