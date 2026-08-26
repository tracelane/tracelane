"use client";

/**
 * SupportForm — the "Reach out" form body (Question / Feedback / Bug + area +
 * message + Send). Extracted from the old slide-out `SupportWidget` so it can
 * render as a full route (`/support`) instead of a right-hand sidebar overlay.
 * Posts to POST /api/support, which persists the message with the session actor.
 */

import { SegmentedControl } from "@tracelanedev/ui";
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
			<div className="rounded-lg border border-seal-line bg-seal-soft p-6 text-center">
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
					className="mt-4 rounded-md bg-action px-4 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90"
				>
					Send another
				</button>
			</div>
		);
	}

	return (
		<div>
			{/*
			 * Kind selector. `aria-pressed` still rides on the selected option — it
			 * is the primitive that sets it now, not this file. The reason it must
			 * not be lost: which tab is selected was once conveyed by COLOUR ALONE,
			 * so a screen reader announced three identical buttons with no selected
			 * state (WCAG 1.4.1 / 4.1.2), and the L16 dead-button sweep could not
			 * tell "correctly inert on re-click" from "wired to nothing".
			 *
			 * `size="md"` reproduces the old `px-3 py-1.5 text-sm` exactly. What it
			 * does NOT reproduce is `flex-1`: the three tabs used to stretch across
			 * the full form width, and the shared control is intrinsically sized.
			 * That is the deliberate change — a full-bleed row of tabs is a fourth
			 * shape for a control the rest of the app renders compactly.
			 */}
			<div className="mb-4">
				<SegmentedControl
					label="What kind of message is this?"
					size="md"
					value={kind}
					options={TABS.map((t) => ({ value: t.key, label: t.label }))}
					onChange={setKind}
				/>
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
				className="mb-4 w-full rounded-sm border border-line bg-surface px-3 py-2 text-sm text-ink focus:border-action-line"
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
				className="h-48 w-full resize-y rounded-sm border border-line bg-surface px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-action-line"
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
					className="rounded-md bg-action px-4 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90 disabled:cursor-not-allowed disabled:opacity-40"
				>
					{status === "sending" ? "Sending…" : "Send"}
				</button>
			</div>
		</div>
	);
}
