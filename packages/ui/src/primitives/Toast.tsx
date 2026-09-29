"use client";
import { Button } from "./Button";
export function Toast({
	message,
	onDismiss,
	tone = "neutral",
}: {
	message: string | null;
	onDismiss: () => void;
	tone?: "neutral" | "danger";
}) {
	if (!message) return null;
	return (
		<div
			role={tone === "danger" ? "alert" : "status"}
			className="fixed bottom-4 right-4 z-50 flex max-w-sm items-center gap-3 rounded-control border border-line bg-surface p-4 text-sm shadow-overlay"
		>
			<span className={tone === "danger" ? "text-danger-ink" : "text-ink"}>
				{message}
			</span>
			<Button
				variant="ghost"
				aria-label="Dismiss notification"
				onClick={onDismiss}
			>
				×
			</Button>
		</div>
	);
}
