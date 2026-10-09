"use client";
/** Small form atoms shared by the Gateway settings pages — design tokens only. */

import { Button } from "@tracelanedev/ui";
import type { ReactNode } from "react";

export const inputClass =
	"w-full rounded-control border border-line bg-surface px-2 py-1.5 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring disabled:opacity-50";
export const monoInput = `${inputClass} font-mono`;

/** A titled card section — the unit every page is built from. */
export function Panel({
	id,
	title,
	description,
	children,
	tone,
}: {
	id?: string;
	title: string;
	description?: ReactNode;
	children: ReactNode;
	/** `danger` draws the red zone (Emergency). */
	tone?: "danger";
}) {
	return (
		<section
			aria-labelledby={id ? `${id}-title` : undefined}
			className={`space-y-3 rounded-card border bg-surface p-5 ${
				tone === "danger" ? "border-danger/40" : "border-line"
			}`}
		>
			<div>
				<h3
					id={id ? `${id}-title` : undefined}
					className={`text-sm font-semibold ${tone === "danger" ? "text-danger-ink" : ""}`}
				>
					{title}
				</h3>
				{description ? (
					<p className="mt-1 text-sm text-ink-2">{description}</p>
				) : null}
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
