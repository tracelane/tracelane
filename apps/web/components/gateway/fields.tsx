"use client";
/** Small form atoms shared by the Gateway settings pages — design tokens only. */

import { Button } from "@tracelanedev/ui";
import { type ReactNode, useId, useState } from "react";

export const inputClass =
	"w-full rounded-control border border-line bg-surface px-2 py-1.5 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring disabled:opacity-50";
export const monoInput = `${inputClass} font-mono`;

/** A titled card section — the unit every page is built from. */
export function Panel({
	id,
	title,
	description,
	note,
	children,
	tone,
}: {
	id?: string;
	title: string;
	/** Explanation; behind the info button (except on a danger panel). */
	description?: ReactNode;
	/** Always visible: a live status line (a limit reached, a plan cap), or a caveat a user
	 * must not miss (data leaving the workspace, best-effort delivery, unreleased features). */
	note?: ReactNode;
	children: ReactNode;
	/** `danger` draws the red zone (Emergency). */
	tone?: "danger";
}) {
	const [open, setOpen] = useState(false);
	const noteId = useId();
	// Founder 2026-11-18: explanations sit behind an info button so pages scroll less.
	// A danger panel (Emergency) keeps its warning in view.
	const collapsible = Boolean(description) && tone !== "danger";
	return (
		<section
			aria-labelledby={id ? `${id}-title` : undefined}
			className={`space-y-3 rounded-card border bg-surface p-5 ${
				tone === "danger" ? "border-danger/40" : "border-line"
			}`}
		>
			<div>
				<div className="flex items-center gap-1.5">
					<h3
						id={id ? `${id}-title` : undefined}
						className={`text-sm font-semibold ${tone === "danger" ? "text-danger-ink" : ""}`}
					>
						{title}
					</h3>
					{collapsible ? (
						<button
							type="button"
							aria-label={`About ${title}`}
							aria-expanded={open}
							aria-controls={open ? noteId : undefined}
							onClick={() => setOpen((v) => !v)}
							className={`inline-flex h-6 w-6 items-center justify-center rounded-full border text-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring ${
								open ? "border-ink text-ink" : "border-line"
							}`}
						>
							<svg
								width="12"
								height="12"
								viewBox="0 0 16 16"
								aria-hidden="true"
							>
								<circle cx="8" cy="4.5" r="1.1" fill="currentColor" />
								<path
									d="M8 7v5"
									stroke="currentColor"
									strokeWidth="1.6"
									strokeLinecap="round"
								/>
							</svg>
						</button>
					) : null}
				</div>
				{description && (!collapsible || open) ? (
					<p id={noteId} className="mt-1 text-sm text-ink-2">
						{description}
					</p>
				) : null}
				{note ? <p className="mt-1 text-sm text-ink-2">{note}</p> : null}
			</div>
			{children}
		</section>
	);
}

/** A labelled input with its hint and the error the gateway (or the form) named for it. */
export function Field({
	label,
	hint,
	error,
	children,
}: {
	label: string;
	hint?: ReactNode;
	error?: string | null;
	children: ReactNode;
}) {
	return (
		// biome-ignore lint/a11y/noLabelWithoutControl: the control is `children`
		<label className="block space-y-1 text-sm">
			<span className="font-medium text-ink">{label}</span>
			{children}
			{hint ? <span className="block text-xs text-ink-3">{hint}</span> : null}
			{error ? (
				<span role="alert" className="block text-xs text-danger-ink">
					{error}
				</span>
			) : null}
		</label>
	);
}

/** Why a control is disabled — always rendered, never a bare greyed-out button. */
export function WhyDisabled({ reason }: { reason: string | null }) {
	if (!reason) return null;
	return (
		<p className="text-xs text-ink-3" data-testid="why-disabled">
			{reason}
		</p>
	);
}

/** The "nothing configured" copy that says the consequence. */
export function EmptyNote({ children }: { children: ReactNode }) {
	return (
		<p className="rounded-control bg-surface-2 px-3 py-2 text-sm text-ink-2">
			{children}
		</p>
	);
}

export function PrimaryButton(props: Parameters<typeof Button>[0]) {
	return <Button variant="primary" size="sm" {...props} />;
}
