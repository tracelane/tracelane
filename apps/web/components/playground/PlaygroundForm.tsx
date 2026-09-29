"use client";
import { fmtBytes, fmtUsd } from "@/lib/metrics/format";

import { apiFetchRaw } from "@/lib/api-fetch";
import { formatDateTimeUtc } from "@/lib/format-date";
import type { PrefillResult } from "@/lib/playground-prefill";
import { buildPromptVersionPayload } from "@/lib/playground-prompt-version";
import type { PlaygroundLimits } from "@/lib/playground-settings";
import {
	render as renderTemplate,
	variablesIn,
} from "@/lib/playground-template";
import { Button, Dialog, StatusBadge, fmtDurMs } from "@tracelanedev/ui";
import { useEffect, useRef, useState } from "react";
export interface PlaygroundModel {
	value: string;
	label: string;
}
type Message = {
	id: string;
	role: "system" | "user" | "assistant" | "tool";
	content: string;
	truncated?: boolean;
};
type Column = {
	id: string;
	model: string;
	temperature: string;
	top_p: string;
	max_tokens: string;
	seed: string;
};
type Result = {
	ok: boolean;
	status: number;
	trace_id: string;
	latency_ms: number;
	response?: {
		content: string;
		model: string;
		usage: { prompt_tokens?: number; completion_tokens?: number } | null;
		tool_calls: unknown[];
		finish_reason: string | null;
	};
	error?: unknown;
};
type History = { ts: string; models: string[]; traceIds: string[] };
const HISTORY_KEY = "tl.playground.history.v2";
function RecordedCost({
	traceId,
	seconds,
}: { traceId: string; seconds: number }) {
	const [state, setState] = useState<{ state: string; cost_usd?: number }>({
		state: "pending",
	});
	useEffect(() => {
		let cancelled = false;
		const controller = new AbortController();
		const start = Date.now();
		let timer: ReturnType<typeof setTimeout>;
		async function poll() {
			try {
				const res = await apiFetchRaw(
					`/api/playground/cost?trace=${encodeURIComponent(traceId)}`,
					{ signal: controller.signal },
				);
				if (res.ok) {
					const data = await res.json();
					if (cancelled) return;
					if (data.state === "priced" || data.state === "unpriced") {
						setState(data);
						return;
					}
				}
			} catch {}
			if (cancelled) return;
			if (Date.now() - start >= seconds * 1000) {
				setState({ state: "expired" });
				return;
			}
			timer = setTimeout(() => void poll(), 2000);
		}
		void poll();
		return () => {
			cancelled = true;
			controller.abort();
			clearTimeout(timer);
		};
	}, [traceId, seconds]);
	return (
		<span>
			{state.state === "priced" && state.cost_usd !== undefined
				? fmtUsd(state.cost_usd)
				: state.state === "unpriced"
					? "Unpriced model"
					: state.state === "expired"
						? "Not recorded yet — open trace"
						: "Recording cost…"}
		</span>
	);
}
function ResultPanel({
	result,
	limits,
}: { result: Result; limits: PlaygroundLimits }) {
	if (!result.ok) {
		const body = result.error;
		const error =
			body && typeof body === "object" ? (body as Record<string, unknown>) : {};
		return (
			<div
				role="alert"
				className="space-y-2 rounded-control border border-danger bg-danger-soft p-4 text-danger-ink"
			>
				<p className="font-semibold">Gateway error ({result.status})</p>
				<pre className="whitespace-pre-wrap break-words text-xs">
					{typeof body === "string" ? body : JSON.stringify(body, null, 2)}
				</pre>
				{typeof error.correlation_id === "string" && (
					<a
						className="underline"
						href={`/guardrails/verdicts?correlation_id=${encodeURIComponent(error.correlation_id)}`}
					>
						View this verdict
					</a>
				)}
			</div>
		);
	}
	const response = result.response;
	return (
		<div className="space-y-4">
			<p className="whitespace-pre-wrap break-words">{response?.content}</p>
			{!!response?.tool_calls?.length && (
				<details open>
					<summary>Tool calls</summary>
					<pre className="whitespace-pre-wrap break-words text-xs">
						{JSON.stringify(response.tool_calls, null, 2)}
					</pre>
				</details>
			)}
			<p className="text-xs text-ink-2">
				{response?.usage
					? `${response.usage.prompt_tokens ?? "—"} in / ${response.usage.completion_tokens ?? "—"} out`
					: "Usage not reported by the provider"}{" "}
				· {fmtDurMs(result.latency_ms)} (includes provider time)
				{response?.finish_reason && ` · ${response.finish_reason}`}
			</p>
			<p className="text-xs">
				<RecordedCost
					traceId={result.trace_id}
					seconds={limits.cost_poll_seconds}
				/>{" "}
				·{" "}
				<a
					className="underline"
					href={`/traces/${encodeURIComponent(result.trace_id)}`}
				>
					Open trace
				</a>
			</p>
		</div>
	);
}
export function PlaygroundForm({
	models,
	limits,
	prefill,
	canRun = false,
	canSave = false,
}: {
	models: PlaygroundModel[];
	limits: PlaygroundLimits;
	prefill?: PrefillResult;
	canRun?: boolean;
	canSave?: boolean;
}) {
	const draft = prefill?.draft;
	const nextId = useRef(1);
	const [system, setSystem] = useState(draft?.system ?? "");
	const [messages, setMessages] = useState<Message[]>(() =>
		draft?.messages.length
			? draft.messages.map((m, i) => ({ ...m, id: `initial-${i}` }))
			: [{ id: "initial-0", role: "user", content: "" }],
	);
	const [columns, setColumns] = useState<Column[]>([
		{
			id: "initial",
			model: draft?.model ?? models[0]?.value ?? "",
			temperature:
				draft?.temperature === undefined ? "" : String(draft.temperature),
			top_p: draft?.top_p === undefined ? "" : String(draft.top_p),
			max_tokens:
				draft?.max_tokens === undefined
					? ""
					: String(Math.min(limits.max_tokens_cap, draft.max_tokens)),
			seed: draft?.seed === undefined ? "" : String(draft.seed),
		},
	]);
	const [toolsText, setToolsText] = useState(
		draft?.tools.length ? JSON.stringify(draft.tools, null, 2) : "",
	);
	const [schemasReady, setSchemasReady] = useState(!draft?.tools.length);
	const [toolChoice, setToolChoice] = useState(
		draft?.tool_choice_mode
			? JSON.stringify(
					draft.tool_choice_mode === "function"
						? {
								type: "function",
								function: { name: draft.tool_choice_function },
							}
						: draft.tool_choice_mode,
				)
			: "",
	);
	const [variables, setVariables] = useState<Record<string, string>>({});
	const [results, setResults] = useState<Result[]>([]);
	const [busy, setBusy] = useState(false);
	const [elapsed, setElapsed] = useState(0);
	const [error, setError] = useState("");
	const [history, setHistory] = useState<History[]>([]);
	const [saveOpen, setSaveOpen] = useState(false);
	const [promptName, setPromptName] = useState("");
	const [saving, setSaving] = useState(false);
	const [saveResult, setSaveResult] = useState<string | null>(null);
	const [saveError, setSaveError] = useState("");
	useEffect(() => {
		try {
			const data = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
			if (Array.isArray(data))
				setHistory(
					data
						.filter(
							(r) =>
								typeof r.ts === "string" &&
								Array.isArray(r.models) &&
								Array.isArray(r.traceIds),
						)
						.slice(0, limits.history_entries),
				);
		} catch {}
	}, [limits.history_entries]);
	useEffect(() => {
		if (!busy) return;
		const start = Date.now();
		setElapsed(0);
		const timer = setInterval(
			() => setElapsed(Math.floor((Date.now() - start) / 1000)),
			1000,
		);
		return () => clearInterval(timer);
	}, [busy]);
	const names = variablesIn(
		[system, ...messages.map((m) => m.content)].join("\n"),
	);
	const missing = names.filter((name) => !Object.hasOwn(variables, name));
	let parsedTools: unknown;
	let parsedChoice: unknown;
	let jsonError = "";
	try {
		if (toolsText.trim()) {
			parsedTools = JSON.parse(toolsText);
			if (!Array.isArray(parsedTools))
				jsonError = "Tools must be a JSON array.";
		}
		if (toolChoice.trim()) parsedChoice = JSON.parse(toolChoice);
	} catch {
		jsonError = "Tools and tool choice must be valid JSON.";
	}
	const body = {
		columns: columns.map((c) => ({
			model: c.model,
			...Object.fromEntries(
				(["temperature", "top_p", "max_tokens", "seed"] as const)
					.filter((k) => c[k].trim() !== "")
					.map((k) => [
						k,
						k === "max_tokens"
							? Math.min(Number(c[k]), limits.max_tokens_cap)
							: Number(c[k]),
					]),
			),
		})),
		system,
		messages: messages.map(({ role, content }) => ({ role, content })),
		...(parsedTools ? { tools: parsedTools } : {}),
		...(parsedChoice !== undefined ? { tool_choice: parsedChoice } : {}),
		variables,
	};
	const bodyBytes = new TextEncoder().encode(JSON.stringify(body)).length;
	const invalidNumbers = columns.some((c) =>
		(["temperature", "top_p", "max_tokens", "seed"] as const).some(
			(k) => c[k] !== "" && !Number.isFinite(Number(c[k])),
		),
	);
	const runnable =
		canRun &&
		!busy &&
		!missing.length &&
		!jsonError &&
		!invalidNumbers &&
		bodyBytes <= limits.max_body_bytes &&
		columns.every((c) => c.model.trim()) &&
		messages.some((m) => m.content.trim()) &&
		(!toolsText.trim() || schemasReady);
	async function run() {
		if (!runnable) return;
		setBusy(true);
		setError("");
		setResults([]);
		try {
			const response = await apiFetchRaw("/api/playground", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(body),
			});
			const data = await response.json();
			if (!response.ok) {
				setError(
					response.status === 403
						? "Viewers can't run prompts — it spends the workspace's provider budget"
						: (data.message ??
								data.error ??
								`Request failed (${response.status})`),
				);
				return;
			}
			setResults(data.columns);
			const entry = {
				ts: new Date().toISOString(),
				models: columns.map((c) => c.model),
				traceIds: (data.columns as Result[])
					.filter((r) => r.ok)
					.map((r) => r.trace_id),
			};
			const updated = [entry, ...history].slice(0, limits.history_entries);
			setHistory(updated);
			try {
				localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
			} catch {}
		} catch {
			setError("The playground did not answer. Retry.");
		} finally {
			setBusy(false);
		}
	}
	async function saveVersion() {
		if (saving || !canSave) return;
		const payload = buildPromptVersionPayload({
			system,
			model: columns[0]?.model ?? "",
		});
		if (!payload.ok) {
			setSaveError(payload.error);
			return;
		}
		setSaving(true);
		setSaveError("");
		setSaveResult(null);
		try {
			const response = await apiFetchRaw(
				`/api/prompts/${encodeURIComponent(promptName.trim())}/versions`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(payload.payload),
				},
			);
			const data = await response.json();
			if (!response.ok) {
				setSaveError(
					response.status === 403
						? "Only a workspace owner can save prompt versions"
						: (data.message ?? data.error ?? "Could not save version."),
				);
				return;
			}
			setSaveResult(`Saved v${data.version_number}`);
		} catch {
			setSaveError("Could not save version. Retry.");
		} finally {
			setSaving(false);
		}
	}
	const columnGrid =
		columns.length === 1
			? "grid-cols-1"
			: columns.length === 2
				? "grid-cols-1 md:grid-cols-2"
				: columns.length === 3
					? "grid-cols-1 md:grid-cols-2 xl:grid-cols-3"
					: "grid-cols-1 md:grid-cols-2 xl:grid-cols-4";
	const field =
		"w-full rounded-control border border-line bg-surface p-2 text-sm";
	return (
		<div className="space-y-6">
			{prefill && (
				<aside className="space-y-2 rounded-control border border-line bg-surface-2 p-4 text-sm">
					<p>
						Restored from span {draft?.sourceSpanId} in trace{" "}
						<a className="underline" href={`/traces/${draft?.sourceTraceId}`}>
							{draft?.sourceTraceId}
						</a>{" "}
						· model, settings and {draft?.messages.length} messages
					</p>
					{prefill.missing.some(
						(m) => m.field === "messages" && m.reason === "capture_off",
					) && (
						<p>
							This workspace doesn't record prompt text, so the messages of this
							call can't be restored. Model and settings were restored.
							{canSave && (
								<>
									{" "}
									<a className="underline" href="/settings/workspace">
										Turn on Record prompt and response text in Settings →
										Workspace to restore future calls.
									</a>
								</>
							)}
						</p>
					)}
					{prefill.missing.some((m) => m.reason === "unrecognized_shape") && (
						<p>
							This span's messages are in a format the playground can't import
							yet. Model and settings restored where present.
						</p>
					)}
					{draft?.systemTruncated && (
						<StatusBadge
							status="truncated"
							tone="warn"
							label={
								<>System truncated when recorded — the rest was not recorded</>
							}
						/>
					)}
					{draft?.max_tokens !== undefined &&
						draft.max_tokens > limits.max_tokens_cap && (
							<p>
								Max tokens clamped from {draft.max_tokens} (the original call)
								to {limits.max_tokens_cap}.
							</p>
						)}
				</aside>
			)}
			<fieldset disabled={busy} className="space-y-4">
				<label className="block space-y-2">
					<span className="font-medium">System prompt</span>
					<textarea
						aria-label="System prompt"
						className={field}
						rows={4}
						value={system}
						onChange={(e) => setSystem(e.target.value)}
					/>
				</label>
				<div className="space-y-3">
					<h2 className="text-sm font-semibold">
						Messages · {messages.length} / {limits.max_messages}
					</h2>
					{messages.map((message, index) => (
						<div
							key={message.id}
							className="rounded-card border border-line bg-surface p-3"
						>
							<div className="mb-2 flex flex-wrap items-center gap-2">
								<label className="text-xs">
									Role {index + 1}
									<select
										aria-label={`Role ${index + 1}`}
										value={message.role}
										onChange={(e) =>
											setMessages((old) =>
												old.map((m) =>
													m.id === message.id
														? { ...m, role: e.target.value as Message["role"] }
														: m,
												),
											)
										}
										className="ml-2 rounded-control border border-line bg-surface p-2"
									>
										{["system", "user", "assistant", "tool"].map((role) => (
											<option key={role}>{role}</option>
										))}
									</select>
								</label>
								<Button
									size="sm"
									disabled={index === 0}
									onClick={() =>
										setMessages((old) => {
											const next = [...old];
											const prev = next[index - 1];
											if (prev) {
												next[index - 1] = message;
												next[index] = prev;
											}
											return next;
										})
									}
								>
									Move up
								</Button>
								<Button
									size="sm"
									disabled={index === messages.length - 1}
									onClick={() =>
										setMessages((old) => {
											const next = [...old];
											const after = next[index + 1];
											if (after) {
												next[index + 1] = message;
												next[index] = after;
											}
											return next;
										})
									}
								>
									Move down
								</Button>
								<Button
									size="sm"
									disabled={messages.length === 1}
									onClick={() =>
										setMessages((old) => old.filter((m) => m.id !== message.id))
									}
								>
									Remove message
								</Button>
								{message.truncated && (
									<StatusBadge
										status="truncated"
										tone="warn"
										label={
											<>Truncated when recorded — the rest was not recorded</>
										}
									/>
								)}
							</div>
							<textarea
								aria-label={`Message ${index + 1}`}
								className={field}
								rows={3}
								value={message.content}
								onChange={(e) =>
									setMessages((old) =>
										old.map((m) =>
											m.id === message.id
												? { ...m, content: e.target.value }
												: m,
										),
									)
								}
							/>
						</div>
					))}
					<Button
						disabled={messages.length >= limits.max_messages}
						onClick={() =>
							setMessages((old) => [
								...old,
								{
									id: `message-${nextId.current++}`,
									role: "user",
									content: "",
								},
							])
						}
					>
						Add message
					</Button>
				</div>
				<details>
					<summary className="cursor-pointer py-2 text-sm font-medium">
						Tools and tool choice
					</summary>
					<div className="space-y-3">
						{!!draft?.tools.length && (
							<p className="text-warn-ink">
								Only tool NAMES are recorded — paste each schema to run with
								tools.
							</p>
						)}
						<label className="block">
							Tools JSON
							<textarea
								className={field}
								rows={6}
								value={toolsText}
								onChange={(e) => setToolsText(e.target.value)}
							/>
						</label>
						{!!draft?.tools.length && (
							<label className="flex gap-2">
								<input
									type="checkbox"
									checked={schemasReady}
									onChange={(e) => setSchemasReady(e.target.checked)}
								/>
								I supplied the tool schemas
							</label>
						)}
						<label className="block">
							Tool choice JSON
							<input
								className={field}
								value={toolChoice}
								onChange={(e) => setToolChoice(e.target.value)}
							/>
						</label>
						{jsonError && (
							<p role="alert" className="text-danger-ink">
								{jsonError}
							</p>
						)}
					</div>
				</details>
				{names.length > 0 && (
					<section className="space-y-3 rounded-card border border-line p-4">
						<h2 className="font-semibold">{names.length} variables</h2>
						{names.map((name) => (
							<div key={name} className="flex flex-wrap items-end gap-2">
								<label className="grow">
									{name}
									<input
										aria-label={`Variable ${name}`}
										className={field}
										value={variables[name] ?? ""}
										onChange={(e) =>
											setVariables((old) => ({
												...old,
												[name]: e.target.value,
											}))
										}
									/>
								</label>
								<Button
									onClick={() =>
										setVariables((old) => ({ ...old, [name]: "" }))
									}
								>
									Use empty
								</Button>
							</div>
						))}
						{missing.length > 0 && (
							<p className="text-xs text-warn-ink">
								Fill variables: {missing.join(", ")}
							</p>
						)}
						<details>
							<summary>Preview rendered messages</summary>
							<pre className="mt-2 whitespace-pre-wrap break-words text-xs">
								{renderTemplate(system, variables).rendered}
								{"\n"}
								{messages
									.map(
										(m) =>
											`${m.role}: ${renderTemplate(m.content, variables).rendered}`,
									)
									.join("\n")}
							</pre>
						</details>
					</section>
				)}
				<div className={`grid gap-4 ${columnGrid}`}>
					{columns.map((column, index) => (
						<section
							key={column.id}
							className="space-y-3 rounded-card border border-line bg-surface p-4"
						>
							<label className="block font-semibold">
								Model {index + 1}
								<input
									aria-label={`Model ${index + 1}`}
									list="playground-models"
									className={field}
									value={column.model}
									onChange={(e) =>
										setColumns((old) =>
											old.map((c) =>
												c.id === column.id
													? { ...c, model: e.target.value }
													: c,
											),
										)
									}
								/>
							</label>
							{(
								[
									["temperature", "Temperature"],
									["top_p", "Top p"],
									["max_tokens", "Max tokens"],
									["seed", "Seed"],
								] as const
							).map(([key, label]) => (
								<label key={key} className="block text-xs">
									{label}
									<input
										aria-label={`${label} ${index + 1}`}
										type="number"
										step="any"
										max={
											key === "max_tokens" ? limits.max_tokens_cap : undefined
										}
										placeholder="Not sent"
										className={field}
										value={column[key]}
										onChange={(e) =>
											setColumns((old) =>
												old.map((c) =>
													c.id === column.id
														? { ...c, [key]: e.target.value }
														: c,
												),
											)
										}
									/>
								</label>
							))}
							<Button
								size="sm"
								disabled={columns.length === 1}
								onClick={() => {
									setColumns((old) => old.filter((c) => c.id !== column.id));
									setResults([]);
								}}
							>
								Remove model
							</Button>
						</section>
					))}
				</div>
				<datalist id="playground-models">
					{models.map((model) => (
						<option key={model.value} value={model.value}>
							{model.label}
						</option>
					))}
				</datalist>
				<Button
					disabled={columns.length >= limits.max_columns}
					title={`Up to ${limits.max_columns} models side by side`}
					onClick={() => {
						setColumns((old) => [
							...old,
							{
								id: `column-${nextId.current++}`,
								model: "",
								temperature: "",
								top_p: "",
								max_tokens: "",
								seed: "",
							},
						]);
						setResults([]);
					}}
				>
					Add model
				</Button>
			</fieldset>
			<div className="flex flex-wrap items-center gap-4">
				<Button
					variant="primary"
					disabled={!runnable}
					onClick={() => void run()}
				>
					{busy ? `Running… ${elapsed}s` : "Run all"}
				</Button>
				<span
					className={`text-xs ${bodyBytes > limits.max_body_bytes ? "text-danger-ink" : "text-ink-2"}`}
				>
					{fmtBytes(bodyBytes)} of {fmtBytes(limits.max_body_bytes)} · one
					provider request per model
				</span>
			</div>
			{!canRun && (
				<p className="text-sm text-ink-2">
					Viewers can't run prompts — it spends the workspace's provider budget
				</p>
			)}
			{error && (
				<p role="alert" className="text-danger-ink">
					{error}
				</p>
			)}
			{(busy || results.length > 0) && (
				<div className={`grid gap-4 ${columnGrid}`}>
					{columns.map((column, index) => (
						<section
							key={column.id}
							className="min-w-0 space-y-3 rounded-card border border-line bg-surface p-4"
						>
							<h2 className="font-mono text-sm">
								{results[index]?.response?.model ?? column.model}
							</h2>
							{busy ? (
								<p aria-live="polite">Running… {elapsed}s</p>
							) : (
								results[index] && (
									<ResultPanel result={results[index]} limits={limits} />
								)
							)}
						</section>
					))}
				</div>
			)}
			{!!draft?.outputMessages.length && (
				<details open className="rounded-card border border-line p-4">
					<summary>Original answer (read-only)</summary>
					{draft.outputMessages.map((m, i) => (
						<p
							key={`${i}:${m.role}`}
							className="mt-3 whitespace-pre-wrap break-words"
						>
							{m.content}
						</p>
					))}
				</details>
			)}
			{results.length === 2 && results.every((r) => r.ok) && (
				<a
					className="inline-block underline"
					href={`/traces/compare?a=${encodeURIComponent(results[0]?.trace_id ?? "")}&b=${encodeURIComponent(results[1]?.trace_id ?? "")}`}
				>
					Compare traces
				</a>
			)}
			<div>
				<Button
					disabled={!canSave || !system.trim()}
					title={
						!canSave
							? "Only a workspace owner can save prompt versions"
							: !system.trim()
								? "A version saves the system prompt; it is empty"
								: undefined
					}
					onClick={() => {
						setSaveOpen(true);
						setSaveResult(null);
						setSaveError("");
					}}
				>
					Save as prompt version
				</Button>
			</div>
			<Dialog
				open={saveOpen}
				title="Save system prompt as version"
				onClose={() => setSaveOpen(false)}
				busy={saving}
			>
				<form
					className="space-y-4"
					onSubmit={(e) => {
						e.preventDefault();
						void saveVersion();
					}}
				>
					<p className="text-sm">
						Saves the system prompt and column 1's model; messages and tools
						stay in the playground. {"{{…}}"} placeholders are stored as
						written; evals and the router send them literally until the prompt
						router renders them.
					</p>
					<label className="block">
						Prompt name
						<input
							className={field}
							value={promptName}
							onChange={(e) => setPromptName(e.target.value)}
							required
						/>
					</label>
					<pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words text-xs">
						{system}
					</pre>
					{saveError && (
						<p role="alert" className="text-danger-ink">
							{saveError}
						</p>
					)}
					{saveResult && <p aria-live="polite">{saveResult}</p>}
					<Button
						type="submit"
						variant="primary"
						disabled={saving || !promptName.trim()}
					>
						{saving ? "Saving…" : "Save version"}
					</Button>
				</form>
			</Dialog>
			<section className="space-y-3 border-t border-line pt-4">
				<h2 className="text-sm font-semibold">
					Run history · last {limits.history_entries}, this browser
				</h2>
				{history.length === 0 ? (
					<p className="text-xs text-ink-2">No runs in this browser yet.</p>
				) : (
					<ul className="space-y-2">
						{history.map((entry) => (
							<li key={entry.ts} className="text-xs text-ink-2">
								{formatDateTimeUtc(entry.ts)} · {entry.models.join(", ")}{" "}
								{entry.traceIds.map((id) => (
									<a
										key={id}
										className="ml-2 underline"
										href={`/traces/${encodeURIComponent(id)}`}
									>
										{id.slice(0, 8)}
									</a>
								))}
							</li>
						))}
					</ul>
				)}
			</section>
		</div>
	);
}
