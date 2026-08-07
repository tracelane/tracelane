"use client";

/**
 * SupportForm — the "Reach out" form body (Question / Feedback / Bug + area +
 * message + Send). Extracted from the old slide-out `SupportWidget` so it can
 * render as a full route (`/support`) instead of a right-hand sidebar overlay.
 * Posts to POST /api/support, which persists the message with the session actor.
 */

import { useState } from "react";

const TABS = [
	{ key: "query", label: "Question" },
	{ key: "feedback", label: "Feedback" },
	{ key: "bug", label: "Bug" },
] as const;
type Kind = (typeof TABS)[number]["key"];

/** Broad product area so a request arrives with routing context. */
const AREAS = [
	{ key: "gateway", label: "Gateway & providers" },
	{ key: "traces", label: "Traces & sessions" },
	{ key: "guardrails", label: "Guardrails" },
	{ key: "audit", label: "Audit ledger" },
	{ key: "billing", label: "Billing & plan" },
	{ key: "account", label: "Account & team" },
	{ key: "other", label: "Something else" },
] as const;

const MAX = 5000;

/** Combine class strings, dropping falsy values. */
function cn(...classes: (string | false | undefined | null)[]): string {
	return classes.filter(Boolean).join(" ");
}

export function SupportForm() {
	const [kind, setKind] = useState<Kind>("query");
	const [message, setMessage] = useState("");
	const [area, setArea] = useState<string>("other");
	const [ref, setRef] = useState<string | null>(null);
	const [status, setStatus] = useState<"idle" | "sending" | "sent" | "error">(
		"idle",
	);

	async function send() {
		const text = message.trim();
		if (!text || text.length > MAX || status === "sending") return;
		setStatus("sending");
		try {
			const res = await fetch("/api/support", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ kind, message: text, category: area }),
			});
			if (!res.ok) throw new Error(`status ${res.status}`);
			const data = (await res.json().catch(() => null)) as {
				ref?: string;
			} | null;
			setRef(data?.ref ?? null);
			setStatus("sent");
			setMessage("");
		} catch {
			setStatus("error");
		}
	}

	const kindLabel = TABS.find((t) => t.key === kind)?.label.toLowerCase();

	if (status === "sent") {
		return (
			<div className="rounded-lg border border-seal-line bg-seal-soft/40 p-6 text-center">
				<p className="text-sm text-ink">
					Thanks — we&apos;ve got your {kindLabel} and will follow up by email.
				</p>
				{ref && (
					<p className="mt-2 text-xs text-ink-2">
						Your reference:{" "}
						<code className="font-mono font-semibold text-ink">{ref}</code>
					</p>
				)}
				<button
					type="button"
					onClick={() => setStatus("idle")}
					className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-on transition-colors hover:bg-accent/90"
				>
					Send another
				</button>
			</div>
		);
	}

	return (
		<div>
			{/* Tabs */}
			<div className="mb-4 flex gap-1 rounded-lg border border-line p-1">
				{TABS.map((t) => (
					<button
						key={t.key}
						type="button"
						onClick={() => setKind(t.key)}
						className={cn(
							"flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal",
							kind === t.key
								? "bg-selected text-selected-on"
								: "text-ink-2 hover:text-ink",
						)}
					>
						{t.label}
					</button>
				))}
			</div>

			{/* Broad area — routes the request; stored with the message. */}
			<label
				htmlFor="support-area"
				className="mb-1 block text-sm font-medium text-ink"
			>
				Area
			</label>
			<select
				id="support-area"
				value={area}
				onChange={(e) => setArea(e.target.value)}
				className="mb-4 w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink outline-none focus:border-accent-line"
			>
				{AREAS.map((a) => (
					<option key={a.key} value={a.key}>
						{a.label}
					</option>
				))}
			</select>

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
						message.length > MAX ? "text-danger-ink" : "text-ink-3",
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
				placeholder="Tell us what's on your mind…"
				className="h-48 w-full resize-y rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink outline-none placeholder:text-ink-3 focus:border-accent-line"
			/>

			{status === "error" && (
				<p className="mt-2 text-sm text-danger-ink">
					Couldn&apos;t send — please try again.
				</p>
			)}

			<div className="mt-5 flex items-center justify-end gap-2">
				<button
					type="button"
					onClick={send}
					disabled={status === "sending" || !message.trim()}
					className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-on transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-40"
				>
					{status === "sending" ? "Sending…" : "Send"}
				</button>
			</div>
		</div>
	);
}
