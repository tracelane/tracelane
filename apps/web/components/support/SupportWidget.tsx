"use client";

/**
 * SupportWidget — the in-product "Reach out" panel (modeled on Polar's support
 * widget). A sidebar trigger opens a right-hand slide-out with three tabs —
 * Question / Feedback / Bug — a bounded message box, and Send. Posts to
 * POST /api/support, which persists the message with the session's actor.
 *
 * Self-contained: renders both its trigger and its overlay (the panel is
 * fixed-positioned, so it lifts out of the sidebar's flow). No portal needed.
 */

import { useState } from "react";

const TABS = [
	{ key: "query", label: "Question" },
	{ key: "feedback", label: "Feedback" },
	{ key: "bug", label: "Bug" },
] as const;
type Kind = (typeof TABS)[number]["key"];

const MAX = 5000;

/** Combine class strings, dropping falsy values. */
function cn(...classes: (string | false | undefined | null)[]): string {
	return classes.filter(Boolean).join(" ");
}

function LifeBuoyIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<circle cx="12" cy="12" r="10" />
			<circle cx="12" cy="12" r="4" />
			<line x1="4.93" y1="4.93" x2="9.17" y2="9.17" />
			<line x1="14.83" y1="14.83" x2="19.07" y2="19.07" />
			<line x1="14.83" y1="9.17" x2="19.07" y2="4.93" />
			<line x1="4.93" y1="19.07" x2="9.17" y2="14.83" />
		</svg>
	);
}

export function SupportWidget() {
	const [open, setOpen] = useState(false);
	const [kind, setKind] = useState<Kind>("query");
	const [message, setMessage] = useState("");
	const [status, setStatus] = useState<"idle" | "sending" | "sent" | "error">(
		"idle",
	);

	function openPanel() {
		setStatus("idle");
		setOpen(true);
	}
	function closePanel() {
		setOpen(false);
	}

	async function send() {
		const text = message.trim();
		if (!text || text.length > MAX || status === "sending") return;
		setStatus("sending");
		try {
			const res = await fetch("/api/support", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ kind, message: text }),
			});
			if (!res.ok) throw new Error(`status ${res.status}`);
			setStatus("sent");
			setMessage("");
		} catch {
			setStatus("error");
		}
	}

	const kindLabel = TABS.find((t) => t.key === kind)?.label.toLowerCase();

	return (
		<>
			<button
				type="button"
				onClick={openPanel}
				className="w-full flex items-center gap-3 rounded-md px-3 py-2 text-sm text-ink-2 hover:bg-surface-2/50 hover:text-ink transition-colors"
			>
				<LifeBuoyIcon />
				Support
			</button>

			{open && (
				<div className="fixed inset-0 z-50 flex justify-end">
					{/* Backdrop — click to dismiss. */}
					<button
						type="button"
						aria-label="Close support panel"
						onClick={closePanel}
						className="absolute inset-0 bg-black/40"
					/>

					<div className="relative z-10 h-full w-full max-w-md overflow-y-auto border-l border-line bg-bg p-6 shadow-xl">
						<div className="mb-5 flex items-center justify-between">
							<h2 className="text-lg font-semibold text-ink">Reach out</h2>
							<button
								type="button"
								onClick={closePanel}
								aria-label="Close"
								className="rounded p-1 text-ink-3 hover:text-ink"
							>
								<svg
									xmlns="http://www.w3.org/2000/svg"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
									strokeWidth={2}
									strokeLinecap="round"
									strokeLinejoin="round"
									className="h-5 w-5"
									aria-hidden="true"
								>
									<line x1="18" y1="6" x2="6" y2="18" />
									<line x1="6" y1="6" x2="18" y2="18" />
								</svg>
							</button>
						</div>

						{status === "sent" ? (
							<div className="rounded-lg border border-line bg-surface-2 p-6 text-center">
								<p className="text-sm text-ink">
									Thanks — we've got your {kindLabel} and will follow up by
									email.
								</p>
								<button
									type="button"
									onClick={closePanel}
									className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-on hover:bg-accent/90 transition-colors"
								>
									Done
								</button>
							</div>
						) : (
							<>
								{/* Tabs */}
								<div className="mb-4 flex gap-1 rounded-lg border border-line p-1">
									{TABS.map((t) => (
										<button
											key={t.key}
											type="button"
											onClick={() => setKind(t.key)}
											className={cn(
												"flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
												kind === t.key
													? "bg-surface-2 text-ink"
													: "text-ink-2 hover:text-ink",
											)}
										>
											{t.label}
										</button>
									))}
								</div>

								{/* Message */}
								<div className="mb-1 flex items-center justify-between">
									<label
										htmlFor="support-message"
										className="text-sm font-medium text-ink"
									>
										Message
									</label>
									<span
										className={cn(
											"text-xs tabular-nums",
											message.length > MAX ? "text-danger" : "text-ink-3",
										)}
									>
										{message.length} / {MAX}
									</span>
								</div>
								<textarea
									id="support-message"
									value={message}
									maxLength={MAX}
									onChange={(e) => setMessage(e.target.value)}
									placeholder="Tell us what's on your mind..."
									className="h-40 w-full resize-y rounded-lg border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 outline-none focus:border-accent-line"
								/>

								{status === "error" && (
									<p className="mt-2 text-sm text-danger">
										Couldn't send — please try again.
									</p>
								)}

								<div className="mt-5 flex items-center justify-end gap-2">
									<button
										type="button"
										onClick={closePanel}
										className="rounded-md px-4 py-2 text-sm text-ink-2 hover:text-ink transition-colors"
									>
										Cancel
									</button>
									<button
										type="button"
										onClick={send}
										disabled={status === "sending" || !message.trim()}
										className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-on hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
									>
										{status === "sending" ? "Sending…" : "Send"}
									</button>
								</div>
							</>
						)}
					</div>
				</div>
			)}
		</>
	);
}
