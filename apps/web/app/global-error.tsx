"use client";

/**
 * Global error boundary — last resort when the root layout itself throws.
 * It replaces the entire document, so it must render its own <html>/<body>,
 * and globals.css is NOT guaranteed to be present. Styles are therefore
 * inline so the page stays branded even with no stylesheet (the exact failure
 * mode where a thrown Server Component previously rendered raw, unstyled HTML).
 */

export default function GlobalError({
	error,
	reset,
}: {
	error: Error & { digest?: string };
	reset: () => void;
}) {
	return (
		<html lang="en">
			<body
				style={{
					margin: 0,
					minHeight: "100vh",
					display: "flex",
					alignItems: "center",
					justifyContent: "center",
					background: "#09090b",
					color: "#fafafa",
					fontFamily:
						"ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
				}}
			>
				<div
					style={{ maxWidth: "28rem", textAlign: "center", padding: "1.5rem" }}
				>
					{/* Inline Chisel mark — self-contained (no CSS vars), since this
					    last-resort page can render with no stylesheet present. */}
					<div
						style={{
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							gap: "0.5rem",
						}}
					>
						<svg
							viewBox="0 0 76 76"
							width={24}
							height={24}
							fill="none"
							role="img"
							aria-label="Tracelane"
						>
							<path
								d="M30 14 L14 14 L14 62 L30 62 L30 56 L20 56 L20 20 L30 20 Z"
								fill="#fafafa"
							/>
							<path
								d="M46 14 L62 14 L62 62 L46 62 L46 56 L56 56 L56 20 L46 20 Z"
								fill="#fafafa"
							/>
							<rect x="20" y="36.4" width="36" height="3.2" fill="#fafafa" />
							<circle
								cx="38"
								cy="38"
								r="9"
								stroke="#fafafa"
								strokeWidth="3.5"
								fill="#09090b"
							/>
							<circle cx="38" cy="38" r="3.2" fill="#fafafa" />
						</svg>
						<span
							style={{
								fontFamily: "ui-monospace, monospace",
								fontSize: "0.9rem",
								fontWeight: 600,
								letterSpacing: "-0.01em",
							}}
						>
							tracelane
						</span>
					</div>
					<h1
						style={{
							fontSize: "1.5rem",
							fontWeight: 600,
							margin: "1rem 0 0.5rem",
						}}
					>
						Something went wrong
					</h1>
					<p
						style={{
							fontSize: "0.875rem",
							color: "#a1a1aa",
							marginBottom: "1.5rem",
						}}
					>
						A critical error occurred while loading the app.
					</p>
					{error.digest && (
						<p
							style={{
								fontSize: "0.75rem",
								fontFamily: "ui-monospace, monospace",
								color: "#52525b",
								marginBottom: "1rem",
							}}
						>
							Reference: {error.digest}
						</p>
					)}
					<button
						type="button"
						onClick={reset}
						style={{
							padding: "0.5rem 1rem",
							borderRadius: "0.5rem",
							border: "none",
							fontSize: "0.875rem",
							fontWeight: 500,
							background: "#fafafa",
							color: "#18181b",
							cursor: "pointer",
						}}
					>
						Try again
					</button>
				</div>
			</body>
		</html>
	);
}
