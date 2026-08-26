import { type HTMLAttributes, forwardRef } from "react";
import { cn } from "../lib/cn";

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
	/**
	 * Differentiator surface (audit/ledger/provenance cards) → a 2px seal-green
	 * strip painted as the card's TOP EDGE (`.card-provenance-top` in tokens.css,
	 * paired here with `border-t-0` so the strip IS the edge). RATIONED: the seal
	 * marks provenance and nothing else — it is one of the very few coloured marks
	 * left in the system, and a second use would make it decoration. Body/utility
	 * cards keep the neutral hairline.
	 */
	provenance?: boolean;
	/**
	 * SECONDARY surface (P0.4). Adds `.surface-card--quiet`, which removes the
	 * card shadow and nothing else — same colour, same border, same radius.
	 *
	 * WHY A BOOLEAN AND NOT A `variant` UNION: the hierarchy has exactly two
	 * levels, and the difference between them is exactly one property. A union
	 * invites a third level, and three levels of card is how a dashboard goes
	 * back to reading as an undifferentiated wall.
	 *
	 * WHO PASSES IT, so the split is a rule rather than a taste call:
	 *  · PRIMARY (default, lifted)  — Traffic, Latency, Error Budget, Request Flow.
	 *    The four surfaces a reader is meant to land on first.
	 *  · SECONDARY (`quiet`, flat)  — Provider Health, Top Models, Failure
	 *    Signatures, Tool Usage, Guardrail Activity. Supporting detail: still a
	 *    card, deliberately not competing for the first glance.
	 *
	 * The lift it removes is ~2% of black across two layers, because on a #fafaf9
	 * ground the card is already separated by TONE — the shadow only says "this
	 * one is in front".
	 */
	quiet?: boolean;
}

export const Card = forwardRef<HTMLDivElement, CardProps>(
	({ className, provenance, quiet, ...props }, ref) => (
		<div
			ref={ref}
			className={cn(
				"surface-card border border-line bg-surface",
				quiet && "surface-card--quiet",
				provenance && "border-t-0 card-provenance-top",
				className,
			)}
			{...props}
		/>
	),
);
Card.displayName = "Card";
