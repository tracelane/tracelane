"use client";

/**
 * /onboarding — new user setup wizard.
 *
 * Three steps:
 *   1. Welcome — confirms workspace is ready.
 *   2. Create API key — shows raw key once; must be copied before proceeding.
 *   3. Quick-start — SDK install + init snippet with the real key substituted.
 *
 * Redirects to /traces on completion. Accessible directly at any time
 * (users may want to create additional keys).
 *
 * Reload safety (V-13): the wizard step and a non-secret "a key was created"
 * marker are persisted to `sessionStorage`, so a mid-flow refresh resumes the
 * current step instead of silently bouncing to step 1. The raw key is NEVER
 * persisted (reveal-once contract — only the SHA-256 hash is stored server
 * side). If a key was created but is no longer in memory after a reload, the
 * UI surfaces an explicit "shown once, create a new one" recovery path rather
 * than dropping it silently. Markers are cleared on completion.
 */

import { VerifyByTrace } from "@/components/onboarding/VerifyByTrace";
import { Logo } from "@tracelanedev/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const TOTAL_STEPS = 3;

// Session-scoped (tab-lifetime) progress keys. Non-secret by design — the raw
// API key is never written to web storage.
const STEP_KEY = "tl_onboarding_step";
const KEY_CREATED_MARKER = "tl_onboarding_key_created";

// ── Step progress indicator ───────────────────────────────────────────────────

function StepProgress({ current }: { current: number }) {
	return (
		<div className="flex items-center gap-2 mb-8">
			{Array.from({ length: TOTAL_STEPS }, (_, i) => (
				// Decorative progress dots — keyed by position because they have
				// no inherent identifier. TOTAL_STEPS is compile-time constant
				// and the array never reorders, so an index-based key is safe.
				// biome-ignore lint/suspicious/noArrayIndexKey: positional
				<div key={`step-${i}`} className="flex items-center gap-2">
					<div
						className={`h-2 w-2 rounded-full transition-colors ${
							i + 1 <= current ? "bg-accent-ink" : "bg-surface-3"
						}`}
					/>
					{i < TOTAL_STEPS - 1 && (
						<div
							className={`h-px w-8 transition-colors ${
								i + 1 < current ? "bg-accent-ink" : "bg-surface-2"
							}`}
						/>
					)}
				</div>
			))}
			<span className="text-xs text-ink-3 ml-2">
				Step {current} of {TOTAL_STEPS}
			</span>
		</div>
	);
}

// ── Step 1 — Welcome ──────────────────────────────────────────────────────────

function StepWelcome({ onNext }: { onNext: () => void }) {
	const [workspace, setWorkspace] = useState("");
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	// Provision the WorkOS organization (Tracelane owns org lifecycle) before
	// advancing. The endpoint is idempotent and re-mints the session cookie so
	// the next step's API-key call is org-scoped. Falls back to a derived
	// workspace name when the field is left blank.
	const start = async () => {
		setLoading(true);
		setError(null);
		try {
			const res = await fetch("/api/onboarding/organization", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: workspace.trim() }),
			});
			if (!res.ok) {
				setError("Couldn't create your workspace — try again.");
				return;
			}
			onNext();
		} catch {
			setError("Network error — try again.");
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="space-y-6">
			<div>
				<h2 className="text-2xl font-semibold text-ink">
					Welcome to Tracelane
				</h2>
				<p className="text-sm text-ink-2 mt-2">
					Name your workspace and we&apos;ll get your first agent trace flowing
					in under two minutes.
				</p>
			</div>

			<div className="grid gap-3">
				{[
					{
						icon: "⚡",
						title: "Drop-in gateway proxy",
						desc: "Point your existing OpenAI or Anthropic client at the gateway. No SDK swap required.",
					},
					{
						icon: "🔍",
						title: "Full-fidelity traces",
						desc: "Every LLM call, tool invocation, and agent step captured as OTel spans.",
					},
					{
						icon: "🛡️",
						title: "Predictive guardrails",
						desc: "MCP rug-pull detection, prompt injection, stuck-loop prediction — inline at the gateway.",
					},
				].map(({ icon, title, desc }) => (
					<div
						key={title}
						className="flex gap-3 rounded-lg border border-line p-4"
					>
						<span className="text-lg shrink-0">{icon}</span>
						<div>
							<p className="text-sm font-medium text-ink">{title}</p>
							<p className="text-xs text-ink-2 mt-0.5">{desc}</p>
						</div>
					</div>
				))}
			</div>

			<div>
				<label
					htmlFor="onboarding-workspace-name"
					className="text-xs font-medium text-ink-2 block mb-1.5"
				>
					Workspace name
				</label>
				<input
					id="onboarding-workspace-name"
					type="text"
					value={workspace}
					onChange={(e) => setWorkspace(e.target.value)}
					placeholder="Acme agents"
					className="w-full rounded-lg border border-line bg-bg px-4 py-2.5 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-2 focus:ring-accent-ink"
				/>
			</div>

			{error && <p className="text-sm text-danger">{error}</p>}

			<button
				type="button"
				onClick={start}
				disabled={loading}
				className="cta-lava w-full py-2.5 rounded-lg text-sm font-medium disabled:opacity-50"
			>
				{loading ? "Creating workspace…" : "Get started →"}
			</button>
		</div>
	);
}

// ── Step 2 — Create API key ───────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
	const [copied, setCopied] = useState(false);

	const copy = async () => {
		await navigator.clipboard.writeText(text);
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	};

	return (
		<button
			type="button"
			onClick={copy}
			className="shrink-0 text-xs px-3 py-1.5 rounded border border-line text-ink-2 hover:text-ink hover:border-ink-3 transition-colors"
		>
			{copied ? "Copied!" : "Copy"}
		</button>
	);
}

function StepApiKey({
	onNext,
	onKeyCreated,
	priorKeyLost,
}: {
	onNext: () => void;
	onKeyCreated: (key: string) => void;
	/** A key was created earlier this session but is no longer in memory
	 * (e.g. after a reload) — it can't be re-shown, so offer a recovery path. */
	priorKeyLost: boolean;
}) {
	const [keyName, setKeyName] = useState("my-agent");
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [rawKey, setRawKey] = useState<string | null>(null);
	const [confirmed, setConfirmed] = useState(false);

	const create = async () => {
		setLoading(true);
		setError(null);
		try {
			const res = await fetch("/api/settings/api-keys", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: keyName.trim() || "my-agent" }),
			});
			if (!res.ok) {
				setError("Failed to create key — try again.");
				return;
			}
			const data = (await res.json()) as { rawKey: string };
			setRawKey(data.rawKey);
			onKeyCreated(data.rawKey);
		} catch {
			setError("Network error — try again.");
		} finally {
			setLoading(false);
		}
	};

	if (rawKey) {
		return (
			<div className="space-y-6">
				<div>
					<h2 className="text-2xl font-semibold text-ink">Your API key</h2>
					<p className="text-sm text-ink-2 mt-2">
						Copy this now — it&apos;s shown once. We only store a SHA-256 hash.
					</p>
				</div>

				<div className="rounded-lg bg-bg border border-line p-4 flex items-center gap-3">
					<code className="text-sm font-mono text-accent-ink break-all flex-1">
						{rawKey}
					</code>
					<CopyButton text={rawKey} />
				</div>

				<p className="text-xs text-ink-3">
					It won&apos;t be shown again after you leave this screen — we never
					store the raw key in your browser. You can always create a replacement
					in{" "}
					<Link
						href="/settings/api-keys"
						className="text-accent-ink hover:underline"
					>
						Settings → API Keys
					</Link>
					.
				</p>

				<label className="flex items-center gap-3 cursor-pointer">
					<input
						type="checkbox"
						checked={confirmed}
						onChange={(e) => setConfirmed(e.target.checked)}
						className="rounded border-line accent-accent"
					/>
					<span className="text-sm text-ink-2">
						I&apos;ve copied and stored this key
					</span>
				</label>

				<button
					type="button"
					onClick={onNext}
					disabled={!confirmed}
					className="cta-lava w-full py-2.5 rounded-lg text-sm font-medium disabled:opacity-40"
				>
					Continue →
				</button>
			</div>
		);
	}

	return (
		<div className="space-y-6">
			<div>
				<h2 className="text-2xl font-semibold text-ink">Create an API key</h2>
				<p className="text-sm text-ink-2 mt-2">
					This key authenticates your agents through the Tracelane gateway. Use
					one key per environment.
				</p>
			</div>

			{priorKeyLost && (
				<div className="rounded-lg border border-line bg-warn-soft p-4">
					<p className="text-sm font-medium text-warn">
						Your earlier key can&apos;t be shown again
					</p>
					<p className="text-sm text-ink-2 mt-1">
						API keys are revealed once at creation and never stored in your
						browser. If you didn&apos;t copy it, create a new one below — or
						manage keys anytime in{" "}
						<Link
							href="/settings/api-keys"
							className="text-accent-ink hover:underline"
						>
							Settings → API Keys
						</Link>
						.
					</p>
				</div>
			)}

			<div>
				<label
					htmlFor="onboarding-key-name"
					className="text-xs font-medium text-ink-2 block mb-1.5"
				>
					Key name
				</label>
				<input
					id="onboarding-key-name"
					type="text"
					value={keyName}
					onChange={(e) => setKeyName(e.target.value)}
					placeholder="my-agent"
					className="w-full rounded-lg border border-line bg-bg px-4 py-2.5 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-2 focus:ring-accent-ink"
				/>
			</div>

			{error && <p className="text-sm text-danger">{error}</p>}

			<button
				type="button"
				onClick={create}
				disabled={loading}
				className="cta-lava w-full py-2.5 rounded-lg text-sm font-medium disabled:opacity-50"
			>
				{loading ? "Creating…" : "Create API key →"}
			</button>
		</div>
	);
}

// ── Step 3 — Quick-start ──────────────────────────────────────────────────────

const GATEWAY_URL =
	process.env.NEXT_PUBLIC_GATEWAY_URL ?? "https://gateway.tracelane.dev";

const LANG_LABELS = {
	python: "Python",
	typescript: "TypeScript",
	curl: "cURL",
	cli: "CLI",
} as const;

function StepQuickstart({
	apiKey,
	onDone,
}: {
	apiKey: string;
	onDone: () => void;
}) {
	const [lang, setLang] = useState<"python" | "typescript" | "curl" | "cli">(
		"python",
	);

	const displayKey = apiKey || "tlane_<your_key>";

	// Point your existing client at the gateway base URL — it routes the call
	// and captures the trace. No SDK install needed for the proxy path.
	const pythonSnippet = `from anthropic import Anthropic

client = Anthropic(
    base_url="${GATEWAY_URL}",
    api_key="${displayKey}",
)

client.messages.create(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Hello"}],
    max_tokens=128,
)`;

	const tsSnippet = `import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "${GATEWAY_URL}/v1",
  apiKey: "${displayKey}",
});

await client.chat.completions.create({
  model: "claude-sonnet-4-6",
  messages: [{ role: "user", content: "Hello" }],
});`;

	const curlSnippet = `curl ${GATEWAY_URL}/v1/chat/completions \\
  -H "Authorization: Bearer ${displayKey}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "claude-sonnet-4-6",
    "messages": [{ "role": "user", "content": "Hello" }]
  }'`;

	const cliSnippet = `export TRACELANE_API_KEY="${displayKey}"

# scaffold Tracelane tracing into the current project
tlane init --endpoint ${GATEWAY_URL}`;

	return (
		<div className="space-y-6">
			<div>
				<h2 className="text-2xl font-semibold text-ink">
					Send your first trace
				</h2>
				<p className="text-sm text-ink-2 mt-2">
					Point your existing LLM client at the Tracelane gateway. It&apos;s
					OpenAI- and Anthropic-compatible — no SDK swap required.
				</p>
			</div>

			{!apiKey && (
				<p className="text-xs text-ink-3">
					Showing a <code className="font-mono">tlane_&lt;your_key&gt;</code>{" "}
					placeholder — paste the key you saved earlier, or{" "}
					<Link
						href="/settings/api-keys"
						className="text-accent-ink hover:underline"
					>
						create a new one
					</Link>
					.
				</p>
			)}

			<div className="flex gap-2">
				{(["python", "typescript", "curl", "cli"] as const).map((l) => (
					<button
						key={l}
						type="button"
						onClick={() => setLang(l)}
						className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
							lang === l ? "bg-surface-3 text-ink" : "text-ink-2 hover:text-ink"
						}`}
					>
						{LANG_LABELS[l]}
					</button>
				))}
			</div>

			{lang === "python" && (
				<div className="space-y-2">
					<p className="text-xs text-ink-2">Install</p>
					<div className="rounded-lg bg-bg border border-line p-3 flex items-center justify-between gap-3">
						<code className="text-xs font-mono text-ink">
							pip install tracelane anthropic
						</code>
						<CopyButton text="pip install tracelane anthropic" />
					</div>
					<p className="text-xs text-ink-2 mt-3">Use</p>
					<div className="rounded-lg bg-bg border border-line p-3 flex items-start justify-between gap-3">
						<pre className="text-xs font-mono text-ink overflow-x-auto whitespace-pre">
							{pythonSnippet}
						</pre>
						<CopyButton text={pythonSnippet} />
					</div>
				</div>
			)}

			{lang === "typescript" && (
				<div className="space-y-2">
					<p className="text-xs text-ink-2">Install</p>
					<div className="rounded-lg bg-bg border border-line p-3 flex items-center justify-between gap-3">
						<code className="text-xs font-mono text-ink">
							npm install @tracelanedev/sdk openai
						</code>
						<CopyButton text="npm install @tracelanedev/sdk openai" />
					</div>
					<p className="text-xs text-ink-2 mt-3">Use</p>
					<div className="rounded-lg bg-bg border border-line p-3 flex items-start justify-between gap-3">
						<pre className="text-xs font-mono text-ink overflow-x-auto whitespace-pre">
							{tsSnippet}
						</pre>
						<CopyButton text={tsSnippet} />
					</div>
				</div>
			)}

			{lang === "curl" && (
				<div className="space-y-2">
					<p className="text-xs text-ink-2">Run</p>
					<div className="rounded-lg bg-bg border border-line p-3 flex items-start justify-between gap-3">
						<pre className="text-xs font-mono text-ink overflow-x-auto whitespace-pre">
							{curlSnippet}
						</pre>
						<CopyButton text={curlSnippet} />
					</div>
					<p className="text-xs text-ink-3">
						The gateway is OpenAI- and Anthropic-compatible — point any HTTP
						client at <code className="font-mono">{GATEWAY_URL}/v1</code> and
						send your normal request.
					</p>
				</div>
			)}

			{lang === "cli" && (
				<div className="space-y-2">
					<p className="text-xs text-ink-2">Install</p>
					<div className="rounded-lg bg-bg border border-line p-3 flex items-center justify-between gap-3">
						<code className="text-xs font-mono text-ink">
							npm install -g @tracelanedev/cli
						</code>
						<CopyButton text="npm install -g @tracelanedev/cli" />
					</div>
					<p className="text-xs text-ink-2 mt-3">Use</p>
					<div className="rounded-lg bg-bg border border-line p-3 flex items-start justify-between gap-3">
						<pre className="text-xs font-mono text-ink overflow-x-auto whitespace-pre">
							{cliSnippet}
						</pre>
						<CopyButton text={cliSnippet} />
					</div>
				</div>
			)}

			<VerifyByTrace />

			<button
				type="button"
				onClick={onDone}
				className="text-[13px] text-ink-2 transition-colors hover:text-ink"
			>
				Skip for now → dashboard
			</button>
		</div>
	);
}

// ── Root wizard ───────────────────────────────────────────────────────────────

export default function OnboardingPage() {
	const router = useRouter();
	const [step, setStep] = useState(1);
	const [createdKey, setCreatedKey] = useState("");
	const [keyCreatedThisSession, setKeyCreatedThisSession] = useState(false);

	// Restore session-scoped progress after a reload. Done in an effect (not a
	// lazy initializer) so the server-rendered markup matches the first client
	// render — no hydration mismatch; we sync from sessionStorage post-mount.
	useEffect(() => {
		const savedStep = sessionStorage.getItem(STEP_KEY);
		if (savedStep) {
			const n = Number(savedStep);
			if (Number.isInteger(n) && n >= 1 && n <= TOTAL_STEPS) setStep(n);
		}
		if (sessionStorage.getItem(KEY_CREATED_MARKER)) {
			setKeyCreatedThisSession(true);
		}
	}, []);

	// Persist the current step so a refresh resumes here instead of step 1.
	useEffect(() => {
		sessionStorage.setItem(STEP_KEY, String(step));
	}, [step]);

	const next = () => setStep((s) => s + 1);

	const done = () => {
		// Onboarding finished — drop the session-scoped progress markers.
		sessionStorage.removeItem(STEP_KEY);
		sessionStorage.removeItem(KEY_CREATED_MARKER);
		router.push("/traces");
	};

	const onKeyCreated = (key: string) => {
		setCreatedKey(key);
		setKeyCreatedThisSession(true);
		// Non-secret marker only — never the raw key (reveal-once contract).
		sessionStorage.setItem(KEY_CREATED_MARKER, "1");
	};

	// A key was minted earlier this session but is no longer in memory (reload):
	// it can't be re-shown, so surface a recovery path instead of a blank form.
	const priorKeyLost = keyCreatedThisSession && !createdKey;

	return (
		<div className="min-h-screen bg-bg flex items-center justify-center p-6">
			<div className="w-full max-w-lg">
				<Logo withWordmark className="mb-8" />

				<StepProgress current={step} />

				{step === 1 && <StepWelcome onNext={next} />}
				{step === 2 && (
					<StepApiKey
						onNext={next}
						onKeyCreated={onKeyCreated}
						priorKeyLost={priorKeyLost}
					/>
				)}
				{step === 3 && <StepQuickstart apiKey={createdKey} onDone={done} />}
			</div>
		</div>
	);
}
