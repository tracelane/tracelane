"use client";

/**
 * PlaygroundForm — the client half of `/playground` (`specs/OBS-16-playground.md`
 * §2, §4, §8). The server shell (`app/playground/page.tsx`) already proved a
 * provider is connected and computed the model list; this component never
 * calls the gateway directly — it posts to `POST /api/playground`, which mints
 * the JWT, generates the trace id, and enforces every limit server-side.
 *
 * History is a per-browser convenience (`localStorage`, last 10 runs) — never
 * durable, never read by anything else. Every access is wrapped in try/catch,
 * the same contract `NoApiKeysPanel` uses: storage can throw (private mode,
 * blocked site data), and a hint must never be able to break the form.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import { Button } from "@tracelanedev/ui";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

export interface PlaygroundModel {
	value: string;
	label: string;
}

interface UsageShape {
	prompt_tokens?: number;
	completion_tokens?: number;
	total_tokens?: number;
}

interface PlaygroundResponse {
	trace_id: string;
	response: {
		content: string;
		model: string;
		usage: UsageShape | null;
		finish_reason: string | null;
	};
	latency_ms: number;
}

interface GatewayErrorBody {
	error?: string;
	message?: string;
	rail?: string;
	reason_code?: string;
	correlation_id?: string;
	budget_usd?: number;
	spent_usd?: number;
	resets_at?: string;
	model?: string;
}

interface HistoryEntry {
	ts: string; // ISO — `formatDateTimeUtc` input
	model: string;
	prompt: string;
	traceId: string;
}

const HISTORY_KEY = "tl.playground.history";
const HISTORY_LIMIT = 10;
const MAX_PROMPT_BYTES = 32 * 1024;
const MAX_TOKENS_CAP = 2048;

function readHistory(): HistoryEntry[] {
	try {
		const raw = window.localStorage.getItem(HISTORY_KEY);
		if (!raw) return [];
		const parsed: unknown = JSON.parse(raw);
		return Array.isArray(parsed) ? (parsed as HistoryEntry[]) : [];
	} catch {
		return [];
	}
}

function writeHistory(entries: HistoryEntry[]): void {
	try {
		window.localStorage.setItem(
			HISTORY_KEY,
			JSON.stringify(entries.slice(0, HISTORY_LIMIT)),
		);
	} catch {
		// Storage unavailable — history is a convenience, never a requirement.
	}
}

/** A single result/error render, keyed by the gateway's own typed shape. */
function ErrorPanel({
	status,
	body,
}: { status: number; body: GatewayErrorBody }) {
	const message = body.message ?? body.error ?? `gateway returned ${status}`;

	// Guardrail block: R2-R7 rails all carry a correlation_id + rail — the
	// product's own detection feature, shown, not swallowed (spec §4).
	if (status === 403 && body.correlation_id) {
		return (
			<div className="rounded-lg border border-danger bg-danger-soft p-3 text-xs text-danger-ink">
				<p className="font-medium">Blocked by an inline guardrail</p>
				<p className="mt-1 text-ink-2">
					Rail: <span className="font-mono text-ink">{body.rail ?? "—"}</span>
					{body.reason_code ? (
						<>
							{" "}
							· reason:{" "}
							<span className="font-mono text-ink">{body.reason_code}</span>
						</>
					) : null}
				</p>
				<Link
					href={`/guardrails/verdicts?correlation_id=${encodeURIComponent(body.correlation_id)}`}
					className="mt-1 inline-block font-medium text-action-ink underline underline-offset-2 hover:opacity-80"
				>
					View this verdict →
				</Link>
			</div>
		);
	}

	if (status === 402) {
		return (
			<div className="rounded-lg border border-danger bg-danger-soft p-3 text-xs text-danger-ink">
				<p className="font-medium">Budget exceeded</p>
				<p className="mt-1 text-ink-2">
					{typeof body.budget_usd === "number" &&
					typeof body.spent_usd === "number"
						? `$${body.spent_usd.toFixed(2)} spent of a $${body.budget_usd.toFixed(2)} monthly budget.`
						: message}
					{body.resets_at ? ` Resets ${body.resets_at}.` : ""}
				</p>
			</div>
		);
	}

	if (status === 429) {
		return (
			<div className="rounded-lg border border-danger bg-danger-soft p-3 text-xs text-danger-ink">
				<p className="font-medium">Rate limited or over quota</p>
				<p className="mt-1 text-ink-2">{message}</p>
			</div>
		);
	}

	return (
		<div className="rounded-lg border border-danger bg-danger-soft p-3 text-xs text-danger-ink">
			<p className="font-medium">
				{status === 413 ? "Prompt too large" : `Gateway error (${status})`}
			</p>
			<p className="mt-1 text-ink-2">{message}</p>
		</div>
	);
}

export function PlaygroundForm({ models }: { models: PlaygroundModel[] }) {
	const [model, setModel] = useState(models[0]?.value ?? "");
	const [system, setSystem] = useState("");
	const [prompt, setPrompt] = useState("");
	const [temperature, setTemperature] = useState(0.2);
	const [maxTokens, setMaxTokens] = useState(512);

	const [status, setStatus] = useState<
		"idle" | "loading" | "success" | "error"
	>("idle");
	const [result, setResult] = useState<PlaygroundResponse | null>(null);
	const [errorState, setErrorState] = useState<{
		status: number;
		body: GatewayErrorBody;
	} | null>(null);
	const [elapsedS, setElapsedS] = useState(0);
	const [history, setHistory] = useState<HistoryEntry[]>([]);

	// Read history once on mount — client-only, so it cannot run during SSR.
	useEffect(() => {
		setHistory(readHistory());
	}, []);

	const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
	useEffect(() => {
		if (status !== "loading") {
			if (timerRef.current) clearInterval(timerRef.current);
			return;
		}
		setElapsedS(0);
		const start = Date.now();
		timerRef.current = setInterval(() => {
			setElapsedS(Math.floor((Date.now() - start) / 1000));
		}, 1000);
		return () => {
			if (timerRef.current) clearInterval(timerRef.current);
		};
	}, [status]);

	const promptBytes = new TextEncoder().encode(prompt).length;
	const overLimit = promptBytes > MAX_PROMPT_BYTES;

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!model || !prompt.trim() || overLimit || status === "loading") return;

		setStatus("loading");
		setResult(null);
		setErrorState(null);

		try {
			const res = await fetch("/api/playground", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					model,
					system: system.trim() || undefined,
					prompt: prompt.trim(),
					temperature,
					max_tokens: maxTokens,
				}),
			});

			const text = await res.text();
			let json: unknown = null;
			try {
				json = text ? JSON.parse(text) : null;
			} catch {
				// non-JSON body — fall through to the generic message below
			}

			if (!res.ok) {
				setStatus("error");
				setErrorState({
					status: res.status,
					body: (json as GatewayErrorBody) ?? {},
				});
				return;
			}

			const data = json as PlaygroundResponse;
			setResult(data);
			setStatus("success");

			const entry: HistoryEntry = {
				ts: new Date().toISOString(),
				model,
				prompt: prompt.trim().slice(0, 80),
				traceId: data.trace_id,
			};
			const next = [entry, ...history].slice(0, HISTORY_LIMIT);
			setHistory(next);
			writeHistory(next);
		} catch (err) {
			setStatus("error");
			setErrorState({
				status: 0,
				body: {
					error: "network_error",
					message: err instanceof Error ? err.message : "network error",
				},
			});
		}
	}

	const isLoading = status === "loading";

	return (
		<div className="space-y-6">
			<form onSubmit={handleSubmit} className="surface-card space-y-4 p-5">
				<div className="grid gap-3 sm:grid-cols-3">
					<div>
						<label htmlFor="pg-model" className="mb-1 block text-xs text-ink-2">
							Model
						</label>
						<select
							id="pg-model"
							value={model}
							onChange={(e) => setModel(e.target.value)}
							disabled={isLoading}
							className="h-9 w-full rounded-lg border border-line bg-surface px-2.5 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						>
							{models.map((m) => (
								<option key={m.value} value={m.value}>
									{m.label}
								</option>
							))}
						</select>
					</div>
					<div>
						<label
							htmlFor="pg-temperature"
							className="mb-1 block text-xs text-ink-2"
						>
							Temperature
						</label>
						<input
							id="pg-temperature"
							type="number"
							min={0}
							max={2}
							step={0.1}
							value={temperature}
							onChange={(e) => setTemperature(Number(e.target.value))}
							disabled={isLoading}
							className="h-9 w-full rounded-lg border border-line bg-surface px-2.5 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						/>
					</div>
					<div>
						<label
							htmlFor="pg-max-tokens"
							className="mb-1 block text-xs text-ink-2"
						>
							Max tokens{" "}
							<span className="text-ink-3">(≤ {MAX_TOKENS_CAP})</span>
						</label>
						<input
							id="pg-max-tokens"
							type="number"
							min={1}
							max={MAX_TOKENS_CAP}
							step={1}
							value={maxTokens}
							onChange={(e) =>
								setMaxTokens(
									Math.max(
										1,
										Math.min(MAX_TOKENS_CAP, Number(e.target.value) || 1),
									),
								)
							}
							disabled={isLoading}
							className="h-9 w-full rounded-lg border border-line bg-surface px-2.5 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						/>
					</div>
				</div>

				<div>
					<label htmlFor="pg-system" className="mb-1 block text-xs text-ink-2">
						System prompt <span className="text-ink-3">(optional)</span>
					</label>
					<textarea
						id="pg-system"
						value={system}
						onChange={(e) => setSystem(e.target.value)}
						rows={2}
						placeholder="You are a helpful assistant."
						disabled={isLoading}
						className="w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					/>
				</div>

				<div>
					<label htmlFor="pg-prompt" className="mb-1 block text-xs text-ink-2">
						Prompt
					</label>
					<textarea
						id="pg-prompt"
						value={prompt}
						onChange={(e) => setPrompt(e.target.value)}
						rows={5}
						placeholder="Summarise…"
						required
						disabled={isLoading}
						className="w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					/>
					{overLimit && (
						<p className="mt-1 text-2xs text-danger-ink">
							{Math.ceil(promptBytes / 1024)} KB — the playground limit is 32
							KB.
						</p>
					)}
				</div>

				<div className="flex items-center justify-end gap-3">
					{isLoading && (
						<span className="text-xs text-ink-3">{elapsedS}s…</span>
					)}
					<Button
						type="submit"
						disabled={isLoading || !model || !prompt.trim() || overLimit}
					>
						{isLoading ? "Running…" : "Run ▶"}
					</Button>
				</div>
			</form>

			{status === "error" && errorState && (
				<ErrorPanel status={errorState.status} body={errorState.body} />
			)}

			{status === "success" && result && (
				<div className="surface-card space-y-3 p-5">
					<h2 className="t-card-title">Result</h2>
					<p className="whitespace-pre-wrap rounded-lg border border-line bg-canvas-sunken p-3 text-sm text-ink">
						{result.response.content || (
							<span className="text-ink-3">(empty response)</span>
						)}
					</p>
					<p className="text-xs text-ink-2">
						<span className="font-mono text-ink">{result.response.model}</span>
						{" · "}
						{result.response.usage
							? `${result.response.usage.prompt_tokens ?? "—"} in / ${
									result.response.usage.completion_tokens ?? "—"
								} out`
							: "usage not reported by the provider"}
						{" · "}
						{(result.latency_ms / 1000).toFixed(1)}s gateway
						{result.response.finish_reason
							? ` · finished: ${result.response.finish_reason}`
							: ""}
						{" — "}
						<Link
							href={`/traces/${result.trace_id}`}
							className="font-medium text-action-ink underline underline-offset-2 hover:opacity-80"
						>
							Open trace →
						</Link>
					</p>
					<p className="text-2xs text-ink-3">
						A playground run is a single gateway span; instrument your app for
						full trees.
					</p>
				</div>
			)}

			{history.length > 0 && (
				<div className="space-y-1.5">
					<h2 className="t-card-title">Recent (this browser)</h2>
					<ul className="space-y-1 text-xs text-ink-2">
						{history.map((h) => (
							<li key={`${h.ts}-${h.traceId}`} className="flex gap-2">
								<span className="shrink-0 text-ink-3">
									{formatDateTimeUtc(h.ts)}
								</span>
								<span className="truncate">{h.prompt}</span>
								<span className="shrink-0 font-mono text-ink-3">{h.model}</span>
								<Link
									href={`/traces/${h.traceId}`}
									className="shrink-0 font-medium text-action-ink underline underline-offset-2 hover:opacity-80"
								>
									trace {h.traceId.slice(0, 8)}…
								</Link>
							</li>
						))}
					</ul>
				</div>
			)}
		</div>
	);
}
