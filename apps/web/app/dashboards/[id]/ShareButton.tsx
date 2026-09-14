"use client";

/**
 * ShareButton — copies the current URL to the clipboard.
 * Extracted from the RSC page because it needs onClick (client-only).
 */

import { useState } from "react";

export function ShareButton() {
	const [copied, setCopied] = useState(false);

	function handleCopy() {
		if (typeof navigator === "undefined") return;
		void navigator.clipboard.writeText(window.location.href).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1500);
		});
	}

	return (
		<button
			type="button"
			onClick={handleCopy}
			className="rounded-[var(--radius-control)] border border-line px-3 py-1.5 text-xs text-ink-2 transition-colors hover:bg-surface-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
		>
			{copied ? "Copied!" : "Share"}
		</button>
	);
}
