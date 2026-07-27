"use client";

/**
 * AuthorVersionForm — in-dashboard form to author a new prompt version.
 *
 * Posts to POST /api/prompts/[name]/versions (Next.js route → gateway with
 * per-user JWT). Authoring is Builder-allowed (any authenticated tenant).
 *
 * Fields:
 *   content            (textarea, required)
 *   model_pin          (text, optional — e.g. "gpt-4o-mini")
 *   template_variables (comma-separated names, optional)
 *
 * On success: shows the new version number + sha256 fingerprint, then calls
 * router.refresh() to reload the RSC env cards with updated data.
 *
 * Honesty: no per-version eval scores are shown here. They are not captured
 * in the create response and must not be fabricated.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

interface CreateVersionResponse {
	prompt_version_id: string;
	prompt_id: string;
	version_number: number;
	content: string;
	model_pin: string | null;
	sha256_hex: string;
}

interface Props {
	promptName: string;
}

type Status = "idle" | "loading" | "success" | "error";

export function AuthorVersionForm({ promptName }: Props) {
	const router = useRouter();
	const [content, setContent] = useState("");
	const [modelPin, setModelPin] = useState("");
	const [templateVars, setTemplateVars] = useState("");
	const [status, setStatus] = useState<Status>("idle");
	const [result, setResult] = useState<CreateVersionResponse | null>(null);
	const [errorMsg, setErrorMsg] = useState("");

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!content.trim()) return;

		setStatus("loading");
		setResult(null);
		setErrorMsg("");

		// Parse comma-separated template_variables; filter blanks.
		const vars: string[] = templateVars
			.split(",")
			.map((v: string) => v.trim())
			.filter((v: string) => v.length > 0);

		const body: {
			content: string;
			model_pin?: string;
			template_variables?: string[];
		} = { content: content.trim() };
		if (modelPin.trim()) body.model_pin = modelPin.trim();
		if (vars.length > 0) body.template_variables = vars;

		try {
			const res = await fetch(
				`/api/prompts/${encodeURIComponent(promptName)}/versions`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(body),
				},
			);

			if (!res.ok) {
				const text = await res.text();
				let msg = `Gateway returned ${res.status}`;
				try {
					const json = JSON.parse(text) as { error?: string; message?: string };
					const detail: string | undefined = json.message ?? json.error;
					if (detail) msg = detail;
				} catch {
					// keep msg as-is
				}
				setStatus("error");
				setErrorMsg(msg);
				return;
			}

			const data = (await res.json()) as CreateVersionResponse;
			setResult(data);
			setStatus("success");
			// Reload the RSC env cards so they reflect the newly authored version.
			router.refresh();
		} catch (err) {
			setStatus("error");
			setErrorMsg(err instanceof Error ? err.message : "Network error");
		}
	}

	function handleReset() {
		setStatus("idle");
		setResult(null);
		setErrorMsg("");
		setContent("");
		setModelPin("");
		setTemplateVars("");
	}

	const isLoading = status === "loading";

	return (
		<div className="rounded-lg border border-line bg-surface p-5 space-y-4">
			<h2 className="text-sm font-semibold text-ink">Author new version</h2>

			{status === "success" && result ? (
				<div className="space-y-3">
					<div className="rounded-md border border-ok bg-ok-soft/40 p-3 text-xs space-y-1">
						<p className="font-semibold text-ok">
							Version {result.version_number} authored
						</p>
						<p className="text-ink-2">
							ID:{" "}
							<span className="font-mono text-ink">
								{result.prompt_version_id}
							</span>
						</p>
						<p className="text-ink-2">
							SHA-256:{" "}
							<span className="font-mono text-ink">
								{result.sha256_hex.slice(0, 16)}…
							</span>
						</p>
						{result.model_pin ? (
							<p className="text-ink-2">
								Model:{" "}
								<span className="font-mono text-ink">{result.model_pin}</span>
							</p>
						) : null}
					</div>
					<p className="text-xs text-ink-2">
						To promote this version to production, copy the ID above and use the
						Promote panel below.
					</p>
					<button
						type="button"
						onClick={handleReset}
						className="text-xs text-accent-ink underline underline-offset-2 hover:opacity-80 transition-opacity"
					>
						Author another version
					</button>
				</div>
			) : (
				<form onSubmit={handleSubmit} className="space-y-3">
					<div>
						<label
							htmlFor="author-content"
							className="block text-xs text-ink-2 mb-1"
						>
							Prompt content
						</label>
						<textarea
							id="author-content"
							value={content}
							onChange={(e) => setContent(e.target.value)}
							rows={6}
							placeholder={
								"You are a helpful assistant.\n\nUser query: {{user_query}}"
							}
							className="w-full rounded-md border border-line bg-bg px-3 py-2 text-xs font-mono text-ink placeholder:text-ink-3 outline-none focus:border-accent-line resize-y"
							required
							disabled={isLoading}
						/>
					</div>

					<div>
						<label
							htmlFor="author-model-pin"
							className="block text-xs text-ink-2 mb-1"
						>
							Model pin{" "}
							<span className="text-ink-3">(optional — e.g. gpt-4o-mini)</span>
						</label>
						<input
							id="author-model-pin"
							type="text"
							value={modelPin}
							onChange={(e) => setModelPin(e.target.value)}
							placeholder="gpt-4o-mini"
							className="w-full rounded-md border border-line bg-bg px-3 py-1.5 text-xs font-mono text-ink placeholder:text-ink-3 outline-none focus:border-accent-line"
							disabled={isLoading}
						/>
					</div>

					<div>
						<label
							htmlFor="author-template-vars"
							className="block text-xs text-ink-2 mb-1"
						>
							Template variables{" "}
							<span className="text-ink-3">(optional — comma-separated)</span>
						</label>
						<input
							id="author-template-vars"
							type="text"
							value={templateVars}
							onChange={(e) => setTemplateVars(e.target.value)}
							placeholder="user_query, context"
							className="w-full rounded-md border border-line bg-bg px-3 py-1.5 text-xs font-mono text-ink placeholder:text-ink-3 outline-none focus:border-accent-line"
							disabled={isLoading}
						/>
					</div>

					{status === "error" ? (
						<div className="rounded-md border border-danger bg-danger-soft/40 p-3 text-xs text-danger">
							{errorMsg || "Unexpected failure — check gateway logs."}
						</div>
					) : null}

					<button
						type="submit"
						disabled={isLoading || !content.trim()}
						className="w-full rounded-md bg-accent px-4 py-2 text-xs font-semibold text-accent-on transition-colors hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed"
					>
						{isLoading ? "Authoring…" : "Author version"}
					</button>
				</form>
			)}
		</div>
	);
}
