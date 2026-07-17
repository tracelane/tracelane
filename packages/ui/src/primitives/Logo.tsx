import { cn } from "../lib/cn";

export interface LogoProps {
	/** pixel height of the logo. Default 26. */
	height?: number;
	/** render the full official logo (Chisel mark + "tracelane"); else the icon. */
	withWordmark?: boolean;
	className?: string;
}

/**
 * Tracelane brand logo — the official Chisel bracket-recorder assets
 * (`public/brand`, ADR-045 / ADR-053). Theme-aware: the light/dark asset is
 * selected from the active `data-theme` by the `.brand-logo*` background-image
 * rules in tokens.css (keyed to our in-app theme, NOT the OS scheme, so it
 * tracks the toggle). The mark is monochrome per the ADR-045 lock.
 *
 * `withWordmark` renders the full horizontal logo (mark + "tracelane");
 * otherwise the square Chisel icon. Both expose the accessible name "Tracelane".
 */
export function Logo({
	height = 26,
	withWordmark = false,
	className,
}: LogoProps) {
	return (
		<span
			role="img"
			aria-label="Tracelane"
			className={cn(
				"inline-block bg-contain bg-left bg-no-repeat align-middle",
				withWordmark ? "brand-logo" : "brand-logo-icon",
				className,
			)}
			style={
				withWordmark
					? { height, aspectRatio: "1229 / 320" }
					: { height, width: height }
			}
		/>
	);
}
