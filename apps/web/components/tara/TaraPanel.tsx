"use client";

/**
 * OBS-40 "Ask Tara" — the TopBar launcher + the panel itself, self-contained
 * in one component (mirrors `NotificationBell`'s button+popover shape).
 *
 * Voice is BROWSER-SIDE ONLY: the mic uses `window.SpeechRecognition` /
 * `window.webkitSpeechRecognition` (no audio ever leaves the browser, no
 * STT vendor) and "read aloud" uses `window.speechSynthesis`. Neither API
 * exists in every browser, so both are feature-detected and degrade to
 * hidden-with-a-tooltip / no-op rather than throwing.
 *
 * Model selection never surfaces as a picker: `pickDefaultTaraModel`
 * (`lib/tara/models.ts`) chooses the tenant's best connected provider, and a
 * tenant with none of the providers Tara knows a model for gets the
 * no-provider state below WITHOUT ever calling `/api/tara` — the whole
 * point of checking `GET /api/settings/provider-keys` first.
 */

import { pickDefaultTaraModel } from "@/lib/tara/models";
import { loadVoices, pickTaraVoice } from "@/lib/tara/voice";
import { useDismiss } from "@/lib/use-dismiss";
import { Tooltip, cn } from "@tracelanedev/ui";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

interface ProviderKeySummary {
	provider_id: string;
	last4: string;
}

interface TaraAnswer {
	answer: string;
	citations: Array<{ trace_id: string; label: string }>;
	trace_id_of_this_conversation: string;
	usage: { input_tokens: number; output_tokens: number };
	tool_calls: Array<{ name: string; ok: boolean }>;
	refused_tool_calls: number;
}

type ProviderStatus = "loading" | "no-provider" | "ready" | "provider-error";
type Phase = "idle" | "listening" | "thinking" | "answer" | "error";
type HistoryTurn = { role: "user" | "assistant"; content: string };

// Minimal ambient shape for the two Web Speech constructors — not in the
// default DOM lib, and both are optional (feature-detected below).
interface MinimalSpeechRecognition {
	lang: string;
	interimResults: boolean;
	continuous: boolean;
	onresult:
		| ((event: {
				results: ArrayLike<ArrayLike<{ transcript: string }>>;
		  }) => void)
		| null;
	onend: (() => void) | null;
	onerror: (() => void) | null;
	start: () => void;
	stop: () => void;
}
type SpeechRecognitionCtor = new () => MinimalSpeechRecognition;
interface SpeechWindow {
	SpeechRecognition?: SpeechRecognitionCtor;
	webkitSpeechRecognition?: SpeechRecognitionCtor;
	speechSynthesis?: SpeechSynthesis;
}

function getSpeechRecognitionCtor(): SpeechRecognitionCtor | undefined {
	if (typeof window === "undefined") return undefined;
	const w = window as unknown as SpeechWindow;
	return w.SpeechRecognition ?? w.webkitSpeechRecognition;
}

function MicIcon() {
	return (
		<svg
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<rect x="9" y="2" width="6" height="12" rx="3" />
			<path d="M5 11a7 7 0 0 0 14 0" />
			<path d="M12 18v4M9 22h6" />
		</svg>
	);
}

function SpeakerIcon({ active }: { active: boolean }) {
	return (
		<svg
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-3.5 w-3.5 shrink-0"
			aria-hidden="true"
		>
			<path d="M4 9v6h4l5 4V5L8 9H4z" />
			{active && <path d="M17 8a5 5 0 0 1 0 8M20 6a8.5 8.5 0 0 1 0 12" />}
		</svg>
	);
}

export function TaraPanel() {
	const [open, setOpen] = useState(false);
	const popoverRef = useDismiss<HTMLDivElement>(open, () => setOpen(false));

	const [providerStatus, setProviderStatus] =
		useState<ProviderStatus>("loading");
	const [defaultModel, setDefaultModel] = useState<{
		providerId: string;
		model: string;
	} | null>(null);

	const [micSupported, setMicSupported] = useState(false);
	const [listening, setListening] = useState(false);
	const [transcript, setTranscript] = useState("");
	const recognitionRef = useRef<MinimalSpeechRecognition | null>(null);

	const [question, setQuestion] = useState("");
	const [phase, setPhase] = useState<Phase>("idle");
	const [answer, setAnswer] = useState<TaraAnswer | null>(null);
	const [errorMessage, setErrorMessage] = useState<string | null>(null);
	const [speaking, setSpeaking] = useState(false);
	const [history, setHistory] = useState<HistoryTurn[]>([]);

	// Check for a usable connected provider ONCE, on mount. This is the only
	// fetch this component makes before the user asks a question — and for a
	// tenant with no usable provider it is the ONLY fetch this component ever
	// makes (spec §7 proof 4 / TESTS: no-provider state, zero calls to
	// /api/tara).
	useEffect(() => {
		let live = true;
		(async () => {
			try {
				const res = await fetch("/api/settings/provider-keys");
				if (!res.ok) {
					if (live) setProviderStatus("provider-error");
					return;
				}
				const keys = (await res.json()) as ProviderKeySummary[];
				if (!live) return;
				const pick = pickDefaultTaraModel(keys.map((k) => k.provider_id));
				if (pick) {
					setDefaultModel(pick);
					setProviderStatus("ready");
				} else {
					setProviderStatus("no-provider");
				}
			} catch {
				if (live) setProviderStatus("provider-error");
			}
		})();
		return () => {
			live = false;
		};
	}, []);

	useEffect(() => {
		setMicSupported(Boolean(getSpeechRecognitionCtor()));
	}, []);

	// "?" opens the panel when the user isn't typing elsewhere — the spec's
	// keyboard-shortcut affordance, kept local to this component rather than
	// wired into the global command palette (out of this build's scope).
	useEffect(() => {
		function onKeyDown(e: KeyboardEvent) {
			if (e.key !== "?" || e.metaKey || e.ctrlKey || e.altKey) return;
			const target = e.target as HTMLElement | null;
			const tag = target?.tagName;
			if (tag === "INPUT" || tag === "TEXTAREA" || target?.isContentEditable)
				return;
			setOpen(true);
		}
		window.addEventListener("keydown", onKeyDown);
		return () => window.removeEventListener("keydown", onKeyDown);
	}, []);

	async function ask(q: string): Promise<void> {
		const trimmed = q.trim();
		if (!trimmed || providerStatus !== "ready" || !defaultModel) return;
		setPhase("thinking");
		setErrorMessage(null);
		try {
			const res = await fetch("/api/tara", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					question: trimmed,
					model: defaultModel.model,
					history: history.slice(-6),
				}),
			});
			const body = (await res.json().catch(() => null)) as
				| (TaraAnswer & {
						error?: string;
						message?: string;
						reason?: "budget" | "quota";
				  })
				| null;
			if (!res.ok) {
				const reason = body?.reason;
				const raw =
					body?.message ?? body?.error ?? `Tara failed (HTTP ${res.status})`;
				setErrorMessage(
					reason === "budget"
						? `Budget limit reached — ${raw}`
						: reason === "quota"
							? `Rate limit / quota reached — ${raw}`
							: raw,
				);
				setPhase("error");
				return;
			}
			if (!body) {
				setErrorMessage("Tara returned an empty response.");
				setPhase("error");
				return;
			}
			setAnswer(body);
			setHistory((h) =>
				[
					...h,
					{ role: "user" as const, content: trimmed },
					{ role: "assistant" as const, content: body.answer },
				].slice(-6),
			);
			setPhase("answer");
			setQuestion("");
		} catch (err) {
			setErrorMessage(
				err instanceof Error ? err.message : "Tara is unreachable.",
			);
			setPhase("error");
		}
	}

	function startListening(): void {
		const Ctor = getSpeechRecognitionCtor();
		if (!Ctor) return;
		const recognition = new Ctor();
		recognition.lang = "en-US";
		recognition.interimResults = true;
		recognition.continuous = false;
		recognition.onresult = (event) => {
			let combined = "";
			for (let i = 0; i < event.results.length; i++)
				combined += event.results[i]?.[0]?.transcript ?? "";
			setTranscript(combined);
		};
		recognition.onend = () => {
			setListening(false);
			setTranscript((t) => {
				if (t.trim()) void ask(t);
				return t;
			});
		};
		recognition.onerror = () => setListening(false);
		recognitionRef.current = recognition;
		setPhase("listening");
		setListening(true);
		setTranscript("");
		recognition.start();
	}

	function stopListening(): void {
		recognitionRef.current?.stop();
	}

	function toggleReadAloud(): void {
		if (typeof window === "undefined") return;
		const w = window as unknown as SpeechWindow;
		if (!w.speechSynthesis) return;
		if (speaking) {
			w.speechSynthesis.cancel();
			setSpeaking(false);
			return;
		}
		if (!answer?.answer) return;
		const synth = w.speechSynthesis;
		synth.cancel();
		setSpeaking(true);
		// Tara is a female voice (founder, 2026-09-07). The browser default is
		// male on most platforms, so pick explicitly; `loadVoices` copes with
		// Chrome's lazily-populated list and never blocks the click for long.
		void loadVoices(synth).then((voices) => {
			const utterance = new SpeechSynthesisUtterance(answer.answer);
			const voice = pickTaraVoice(voices);
			if (voice) {
				utterance.voice = voice;
				utterance.lang = voice.lang;
			}
			utterance.rate = 1;
			utterance.pitch = 1;
			utterance.onend = () => setSpeaking(false);
			utterance.onerror = () => setSpeaking(false);
			synth.speak(utterance);
		});
	}

	const trigger = (
		<button
			type="button"
			onClick={() => setOpen((v) => !v)}
			aria-label="Ask Tara"
			aria-expanded={open}
			className="flex h-9 shrink-0 items-center gap-1.5 rounded-[var(--radius-control)] border border-line bg-surface px-3 text-ink-2 text-sm transition-colors hover:border-line-2 hover:text-ink"
		>
			<MicIcon />
			<span className="max-sm:hidden">Ask Tara</span>
		</button>
	);

	return (
		<div className="relative" ref={popoverRef}>
			{trigger}

			{open && (
				// Non-modal popover, same shape as NotificationBell's panel beside
				// it — deliberately no `role="dialog"` (that role pairs with the
				// native <dialog> element's modal semantics; this popover leaves the
				// page behind it live and dismissible by Escape/outside-click via
				// `useDismiss`, not by a backdrop).
				<div className="absolute right-0 z-50 mt-2 w-[26rem] rounded-[var(--radius-card)] border border-line bg-surface p-4 shadow-[var(--shadow-overlay)]">
					<div className="mb-3 flex items-center justify-between">
						<span className="font-medium text-ink">Ask Tara</span>
						<button
							type="button"
							onClick={() => setOpen(false)}
							aria-label="Close"
							className="text-ink-3 hover:text-ink"
						>
							✕
						</button>
					</div>

					{providerStatus === "loading" && (
						<p className="text-sm text-ink-3">Loading…</p>
					)}

					{providerStatus === "provider-error" && (
						<p role="alert" className="text-sm text-ink-2">
							Couldn&apos;t check your connected providers. Try again shortly.
						</p>
					)}

					{providerStatus === "no-provider" && (
						<p className="text-sm text-ink-2">
							Tara needs a connected provider —{" "}
							<Link href="/settings/providers" className="underline">
								add one in Settings → LLM providers
							</Link>
							.
						</p>
					)}

					{providerStatus === "ready" && (
						<div className="space-y-3">
							{phase === "listening" && (
								<p className="text-sm text-ink">
									<span
										aria-hidden="true"
										className="mr-1.5 inline-block animate-pulse text-accent-warm"
									>
										●
									</span>
									Listening…{" "}
									{transcript && (
										<span className="text-ink-2">&quot;{transcript}&quot;</span>
									)}
								</p>
							)}

							{phase === "thinking" && (
								<p className="text-sm text-ink-3">Reading your traces…</p>
							)}

							{phase === "error" && errorMessage && (
								<p role="alert" className="text-sm text-ink-2">
									{errorMessage}
								</p>
							)}

							{phase === "answer" && answer && (
								<div className="space-y-2 border-line border-b pb-3">
									<p className="whitespace-pre-wrap text-ink text-sm">
										{answer.answer}
									</p>
									{answer.citations.length > 0 && (
										<div className="flex flex-wrap gap-1.5">
											{answer.citations.map((c) => (
												<Link
													key={c.trace_id}
													href={`/traces/${c.trace_id}`}
													className="rounded-full border border-line bg-surface-2 px-2 py-0.5 font-mono text-2xs text-ink-2 hover:text-ink"
												>
													{c.label}
												</Link>
											))}
										</div>
									)}
									{answer.refused_tool_calls > 0 && (
										<p className="text-2xs text-ink-3">
											{answer.refused_tool_calls === 1
												? "One lookup was refused (invalid arguments) — the answer may be partial."
												: `${answer.refused_tool_calls} lookups were refused (invalid arguments) — the answer may be partial.`}
										</p>
									)}
									<div className="flex items-center gap-2 text-2xs text-ink-3">
										<span>
											read {answer.tool_calls.length} source
											{answer.tool_calls.length === 1 ? "" : "s"} ·{" "}
											{answer.usage.input_tokens + answer.usage.output_tokens}{" "}
											tokens
										</span>
										{typeof window !== "undefined" &&
											Boolean(
												(window as unknown as SpeechWindow).speechSynthesis,
											) && (
												<button
													type="button"
													onClick={toggleReadAloud}
													aria-pressed={speaking}
													className={cn(
														"inline-flex items-center gap-1 underline",
														// DSH-16: amber while actually speaking — the same
														// "capturing/active right now" signal as the mic,
														// not the ink the control otherwise inherits.
														speaking && "text-accent-warm-ink",
													)}
												>
													<SpeakerIcon active={speaking} />{" "}
													{speaking ? "stop" : "read aloud"}
												</button>
											)}
									</div>
									<p className="text-2xs text-ink-3">
										this question was itself recorded —{" "}
										<Link
											href={`/traces/${answer.trace_id_of_this_conversation}`}
											className="underline"
										>
											open its trace
										</Link>
									</p>
								</div>
							)}

							<form
								onSubmit={(e) => {
									e.preventDefault();
									void ask(question);
								}}
								className="flex items-center gap-2"
							>
								<input
									type="text"
									value={question}
									onChange={(e) => setQuestion(e.target.value)}
									placeholder="type a question…"
									disabled={phase === "thinking" || phase === "listening"}
									className="h-9 flex-1 rounded-[var(--radius-control)] border border-line bg-canvas-sunken px-3 text-ink text-sm focus-visible:border-line-2"
								/>
								{micSupported ? (
									<button
										type="button"
										onClick={listening ? stopListening : startListening}
										disabled={phase === "thinking"}
										aria-label={listening ? "Stop listening" : "Ask by voice"}
										aria-pressed={listening}
										className={cn(
											"flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition-colors",
											// DSH-16: amber + a soft pulse while the mic is actually
											// listening — the recorder's own indicator light, rather
											// than the neutral chip the button otherwise is.
											listening
												? "animate-pulse bg-accent-warm-soft text-accent-warm-ink"
												: "bg-surface-2 text-ink hover:bg-surface-3",
										)}
									>
										<MicIcon />
									</button>
								) : (
									<Tooltip content="Voice input needs Chrome or Edge">
										<span
											aria-hidden="true"
											className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-surface-2 text-ink-3 opacity-50"
										>
											<MicIcon />
										</span>
									</Tooltip>
								)}
								<button
									type="submit"
									disabled={
										phase === "thinking" ||
										phase === "listening" ||
										question.trim().length === 0
									}
									aria-label="Ask"
									className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-action text-action-on disabled:opacity-40"
								>
									↵
								</button>
							</form>
						</div>
					)}
				</div>
			)}
		</div>
	);
}
