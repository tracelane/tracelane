"use client";

/**
 * NewPromptForm — the create-prompt entry point on the list page.
 *
 * A prompt "exists" once its first version is authored, so there is no separate
 * create endpoint: enter a name → navigate to /prompts/[name], where the
 * detail page's AuthorVersionForm authors version 1 (Builder-allowed). This is
 * the discoverable path for the FIRST prompt (the empty state's API snippets are
 * the reference for programmatic authoring).
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

export function NewPromptForm() {
	const router = useRouter();
	const [name, setName] = useState("");

	function go(e: React.FormEvent) {
		e.preventDefault();
		const slug = name.trim();
		if (!slug) return;
		router.push(`/prompts/${encodeURIComponent(slug)}`);
	}

	return (
		<form onSubmit={go} className="flex w-full items-center gap-2 sm:w-auto">
			<input
				value={name}
				onChange={(e) => setName(e.target.value)}
				placeholder="new-prompt-name"
				aria-label="New prompt name"
				className="w-full min-w-0 rounded-md border border-line bg-bg px-3 py-1.5 font-mono text-xs text-ink outline-none placeholder:text-ink-3 focus:border-accent-line sm:w-44"
			/>
			<button
				type="submit"
				disabled={!name.trim()}
				className="shrink-0 whitespace-nowrap rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-accent-on transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-40"
			>
				New prompt →
			</button>
		</form>
	);
}
