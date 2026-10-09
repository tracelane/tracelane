"use client";
import { apiFetch } from "@/lib/api-fetch";
import { inferSpanKind } from "@/lib/span-kind";
import { useEffect, useState } from "react";
import { ConversationMessages } from "./ConversationMessages";
import type { Span } from "./types";

const isMissing = (value: unknown) =>
	value !== null &&
	typeof value === "object" &&
	"missing" in value &&
	value.missing === true;
const isMessage = (value: unknown) =>
	typeof value === "string" ||
	(value !== null &&
		typeof value === "object" &&
		!Array.isArray(value) &&
		("content" in value || "parts" in value));
const valid = (value: unknown) =>
	value === undefined ||
	(Array.isArray(value) ? value.every(isMessage) : isMessage(value));

export function ConversationPanel({
	span,
	attrs,
	readable,
	llmSpans = [],
	onSelectSpan,
	conversationLimit = 50,
}: {
	span: Span;
	attrs: Record<string, unknown>;
	readable: boolean;
	llmSpans?: Span[];
	onSelectSpan?: (id: string) => void;
	conversationLimit?: number;
}) {
	const [capture, setCapture] = useState<{
		effective?: { input: boolean; output: boolean };
		can_edit?: boolean;
	} | null>(null);
	const [expanded, setExpanded] = useState(false);
	useEffect(() => {
		let active = true;
		apiFetch<{
			effective: { input: boolean; output: boolean };
			can_edit: boolean;
		}>("/api/settings/content-capture")
			.then((data) => {
				if (active) setCapture(data);
			})
			.catch(() => {});
		return () => {
			active = false;
		};
	}, []);
	if (inferSpanKind(span.attributes) !== "llm") return null;
	const input = attrs.gen_ai_input_messages;
	const output = attrs.gen_ai_output_messages;
	const system = attrs.gen_ai_system_instructions;
	const unloaded = [input, output, system].some(isMissing);
	const unreadable =
		!readable ||
		!valid(input) ||
		!valid(output) ||
		(system !== undefined && typeof system !== "string");
	const inputs = Array.isArray(input)
		? input
		: input === undefined
			? []
			: [input];
	const outputs = Array.isArray(output)
		? output
		: output === undefined
			? []
			: [output];
	const hasText =
		typeof system === "string" || inputs.length > 0 || outputs.length > 0;
	const limit = Math.max(1, conversationLimit);
	const shown = expanded ? inputs : inputs.slice(-limit);
	const omitted =
		typeof attrs.tracelane_input_messages_omitted === "number" &&
		attrs.tracelane_input_messages_omitted > 0
			? attrs.tracelane_input_messages_omitted
			: 0;
	return (
		<section
			aria-label="Conversation"
			className="space-y-3 rounded-card border border-line bg-surface-2 p-3 text-sm"
		>
			<h3 className="t-metric-label">Conversation</h3>
			{llmSpans.length > 1 && (
				<div className="flex flex-wrap gap-2 text-xs">
					<span>{llmSpans.length} LLM calls in this trace</span>
					{llmSpans.map((item, index) => (
						<button
							type="button"
							key={item.span_id}
							onClick={() => onSelectSpan?.(item.span_id)}
							aria-current={item.span_id === span.span_id ? "true" : undefined}
							className="text-action-ink underline"
						>
							Call {index + 1}
						</button>
					))}
				</div>
			)}
			{unloaded ? (
				<p>Stored text could not be loaded — retry.</p>
			) : unreadable ? (
				<p>Recorded in a shape this view cannot read.</p>
			) : !hasText &&
				capture?.effective?.input === false &&
				capture?.effective?.output === false ? (
				<p>
					No text was recorded for this call. Tracelane records message text
					only when the workspace owner turns on content capture (Settings →
					Workspace). Recorded regardless: token counts, cost, model, finish
					reason, tool names and argument sizes.{" "}
					{capture.can_edit && (
						<a href="/settings/workspace" className="text-action-ink underline">
							Content capture settings
						</a>
					)}
				</p>
			) : !hasText ? (
				<p>
					This call has no recorded text — capture was off when it ran, or this
					route does not record it yet (/v1/messages responses, cache-served
					responses).
				</p>
			) : (
				<>
					{typeof system === "string" && (
						<div>
							<p className="mb-1 text-xs font-semibold uppercase text-ink-2">
								System instructions
							</p>
							<details open={system.length <= 500}>
								<summary className="cursor-pointer text-xs">
									System prompt
								</summary>
								<p className="whitespace-pre-wrap break-words">{system}</p>
							</details>
						</div>
					)}
					{omitted > 0 && (
						<p className="text-xs text-ink-2">
							Showing the newest {inputs.length} of {inputs.length + omitted}{" "}
							messages recorded for this call (recording size cap) — the model
							received all of them.
						</p>
					)}
					{inputs.length > limit && !expanded && (
						<p className="text-xs text-ink-2">
							Showing newest {limit} of {inputs.length} recorded messages.{" "}
							<button
								type="button"
								className="text-action-ink underline"
								onClick={() => setExpanded(true)}
							>
								Show all {inputs.length} messages
							</button>
						</p>
					)}
					{shown.length > 0 && (
						<div>
							<p className="mb-2 text-xs font-semibold uppercase text-ink-2">
								Input
							</p>
							<ConversationMessages value={shown} />
						</div>
					)}
					{outputs.length > 0 && (
						<div>
							<p className="mb-2 text-xs font-semibold uppercase text-ink-2">
								Output
							</p>
							<ConversationMessages value={outputs} />
						</div>
					)}
				</>
			)}
			{span.intervention === 2 && outputs.length === 0 && (
				<p>
					Blocked by a guardrail — no response text is stored for a blocked
					response.
				</p>
			)}
		</section>
	);
}
