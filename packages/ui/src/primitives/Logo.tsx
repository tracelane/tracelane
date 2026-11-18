import { cn } from "../lib/cn";

export interface LogoProps {
	height?: number;
	withWordmark?: boolean;
	className?: string;
}

/** Shared product lockup. The mark file is traced from the founder's 2026-10-12 raster.
 * CSS masks preserve its alpha cut while currentColor follows the app theme. */
export function Logo({
	height = 26,
	withWordmark = false,
	className,
}: LogoProps) {
	const wordmarkPx = Math.round(height * (18 / 26));
	const gapPx = Math.round(height * (10 / 26));
	return (
		<span
			role="img"
			aria-label="Tracelane"
			className={cn("inline-flex items-center align-middle", className)}
			style={{ color: "var(--logo-ink)", gap: withWordmark ? gapPx : 0 }}
		>
			<span
				aria-hidden="true"
				style={{
					width: height,
					height,
					flexShrink: 0,
					display: "block",
					backgroundColor: "currentColor",
					mask: "url('/brand/tracelane-mark.svg') center / contain no-repeat",
					WebkitMask:
						"url('/brand/tracelane-mark.svg') center / contain no-repeat",
				}}
			/>
			{withWordmark && (
				<span
					style={{
						fontFamily: "var(--font-display, Geist, sans-serif)",
						fontWeight: 600,
						fontSize: wordmarkPx,
						letterSpacing: "-0.025em",
						lineHeight: 1,
					}}
				>
					tracelane
				</span>
			)}
		</span>
	);
}
