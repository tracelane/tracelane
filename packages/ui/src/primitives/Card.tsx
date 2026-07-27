import { type HTMLAttributes, forwardRef } from "react";
import { cn } from "../lib/cn";

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
	/**
	 * Differentiator surface (audit/ledger/provenance/metric cards) → a 3px
	 * Verify-green gradient top edge (ADR-053). RATIONED: the Verify seal marks
	 * provenance only. Body/utility cards keep the neutral line.
	 */
	provenance?: boolean;
}

export const Card = forwardRef<HTMLDivElement, CardProps>(
	({ className, provenance, ...props }, ref) => (
		<div
			ref={ref}
			className={cn(
				"rounded-xl border border-line bg-surface",
				provenance && "border-t-0 card-provenance-top",
				className,
			)}
			{...props}
		/>
	),
);
Card.displayName = "Card";
