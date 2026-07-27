"use client";

/**
 * CopyButton — small clipboard affordance for the trace viewer (V-5).
 *
 * Copies a literal `value`, or — with `copyLocation` — the current permalink
 * (`window.location.href`) at click time. Fails silently if the Clipboard API
 * is unavailable (insecure context / denied permission): the underlying text
 * stays selectable, so this is an enhancement, never a dead-end.
 */

import { useState } from "react";

export function CopyButton({
	value,
	copyLocation = false,
	label = "Copy",
	className,
}: {
	value?: string;
	copyLocation?: boolean;
	label?: string;
	className?: string;
}) {
	const [copied, setCopied] = useState(false);

	const copy = async () => {
		const text = copyLocation ? window.location.href : (value ?? "");
		if (!text) return;
		try {
			await navigator.clipboard.writeText(text);
			setCopied(true);
			setTimeout(() => setCopied(false), 1500);
		} catch {
			/* clipboard blocked — value remains selectable, no dead control */
		}
	};

	return (
		<button
			type="button"
			onClick={copy}
			aria-label={copied ? "Copied" : label}
			className={
				className ??
				"shrink-0 rounded border border-line px-2 py-0.5 text-[11px] font-medium text-ink-2 transition-colors hover:border-ink-3 hover:text-ink"
			}
		>
			{copied ? "Copied" : label}
		</button>
	);
}
