/**
 * `tlane init claude-code` — PLT-46.
 *
 * Merges the OTel env block Claude Code needs into a `.claude/settings.json`
 * so every Claude Code session exports its trace tree to the Tracelane
 * gateway. Two things this file deliberately does NOT do:
 *
 *  - It never overwrites a key already present in `settings.json`'s `env`
 *    object — same non-destructive contract as `tlane init`'s `.env` merge
 *    (`init-detect.ts:mergeEnv`), because `settings.json` is a real config
 *    file a developer may have already tuned.
 *  - It never fabricates a scope check. `GET /v1/auth/whoami`
 *    (`crates/gateway/src/server.rs:1359`) returns only `tenant_id` and
 *    `auth_method` — no scopes, read from the handler on 2026-09-06. So the
 *    `ingest`-scope refusal here is NOT read off `whoami`; it comes from a
 *    dry `POST /v1/traces` with an empty OTLP/JSON batch
 *    (`{"resourceSpans":[]}`), which the gateway's own handler decodes to
 *    zero spans and accepts (`crates/gateway/src/trace_ingest.rs`, "An OTLP
 *    exporter with nothing to send is not an error") — so a 403 from that
 *    probe is unambiguously the scope gate at `trace_ingest.rs:207`, not a
 *    malformed request.
 *  - The same shape covers `--proxy`'s `chat`-scope check (`GWY-47`): a dry
 *    `POST /v1/messages` with `{}` reaches the scope gate — which sits
 *    immediately after authentication in
 *    `crates/gateway/src/anthropic_messages.rs` — and then fails body parsing
 *    with a 400 BEFORE the rate limiter, the monthly quota, the audit publish
 *    and the BYOK lookup. So a 403 is unambiguously the scope gate, a 400 means
 *    the scope is present, and nothing is dispatched, metered or ledgered either
 *    way.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DEFAULT_GATEWAY = "https://gateway.tracelane.dev";

/**
 * The exact nine variables from spec `PLT-46` §2, plus — under `--proxy` —
 * the two from `GWY-47` §8. Order matches the spec tables so `--print` output
 * is stable and diffable, and the proxy pair is APPENDED so a non-proxy run
 * emits byte-identical output to before.
 *
 * The two paths are independent and compose: the nine OTel variables export
 * Claude Code's own trace tree over OTLP, while `ANTHROPIC_BASE_URL` +
 * `ANTHROPIC_AUTH_TOKEN` route each API call through the gateway so it becomes
 * a span and a ledger row. Neither replaces the other.
 */
export function buildClaudeCodeEnv(
	gateway: string,
	apiKey: string,
	proxy = false,
): Record<string, string> {
	const base = gateway.replace(/\/$/, "");
	if (proxy) {
		return {
			...buildClaudeCodeEnv(gateway, apiKey),
			// Claude Code sends `Authorization: Bearer $ANTHROPIC_AUTH_TOKEN`; the
			// gateway also accepts `x-api-key` on /v1/messages for SDKs configured
			// with ANTHROPIC_API_KEY. AUTH_TOKEN is the one Claude Code reads.
			ANTHROPIC_BASE_URL: base,
			ANTHROPIC_AUTH_TOKEN: apiKey,
		};
	}
	return {
		CLAUDE_CODE_ENABLE_TELEMETRY: "1",
		CLAUDE_CODE_ENHANCED_TELEMETRY_BETA: "1",
		OTEL_TRACES_EXPORTER: "otlp",
		OTEL_METRICS_EXPORTER: "none",
		OTEL_LOGS_EXPORTER: "none",
		OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
		OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: `${base}/v1/traces`,
		OTEL_EXPORTER_OTLP_HEADERS: `Authorization=Bearer ${apiKey}`,
		OTEL_RESOURCE_ATTRIBUTES:
			"service.name=claude-code,gen_ai.agent.name=claude-code",
	};
}

/** `--print`'s second form: `export KEY=value` lines, shell-quoted. */
export function envAsShellExports(env: Record<string, string>): string {
	return Object.entries(env)
		.map(([k, v]) => `export ${k}='${v.replace(/'/g, "'\\''")}'`)
		.join("\n");
}

export type KeyCheck =
	| { ok: true; tenantId: string }
	| { ok: false; status: number; message: string };

/**
 * Validate the key against `GET /v1/auth/whoami`.
 *
 * `whoami` does not expose scopes (see module docs) — this only proves the
 * credential itself is live. `fetchImpl` is injectable for tests, matching
 * `replay.ts:fetchSpans`.
 */
export async function checkWhoami(
	gateway: string,
	apiKey: string,
	fetchImpl: typeof fetch = fetch,
): Promise<KeyCheck> {
	const base = gateway.replace(/\/$/, "");
	let res: Response;
	try {
		res = await fetchImpl(`${base}/v1/auth/whoami`, {
			headers: { Authorization: `Bearer ${apiKey}` },
		});
	} catch (err) {
		return {
			ok: false,
			status: 0,
			message: `could not reach ${base}: ${(err as Error).message}`,
		};
	}
	const body = await res.json().catch(() => ({}) as Record<string, unknown>);
	if (!res.ok) {
		const message =
			typeof (body as { error?: unknown }).error === "string"
				? (body as { error: string }).error
				: `whoami returned ${res.status}`;
		return { ok: false, status: res.status, message };
	}
	return {
		ok: true,
		tenantId: String((body as { tenant_id?: unknown }).tenant_id ?? ""),
	};
}

export type ScopeCheck =
	| { verdict: "ok" }
	| { verdict: "missing_ingest"; message: string }
	| { verdict: "undetermined"; status: number };

/**
 * Probe the `ingest` scope with a dry, empty OTLP/JSON export.
 *
 * See the module docs for why an empty batch is a safe, side-effect-free way
 * to reach the scope gate at `trace_ingest.rs:207` without publishing
 * anything: zero spans means zero NATS publishes even on a 200.
 */
export async function checkIngestScope(
	gateway: string,
	apiKey: string,
	fetchImpl: typeof fetch = fetch,
): Promise<ScopeCheck> {
	const base = gateway.replace(/\/$/, "");
	let res: Response;
	try {
		res = await fetchImpl(`${base}/v1/traces`, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${apiKey}`,
				"content-type": "application/json",
			},
			body: JSON.stringify({ resourceSpans: [] }),
		});
	} catch {
		// A network failure here says nothing about the scope — don't block on it.
		return { verdict: "undetermined", status: 0 };
	}
	if (res.status === 403) {
		const body = await res.json().catch(() => ({}) as Record<string, unknown>);
		const nested = (body as { error?: { message?: string } }).error;
		const message: string =
			typeof nested === "object" && typeof nested?.message === "string"
				? nested.message
				: "This API key is not scoped to send traces. It needs the `ingest` scope; mint a new key with it in Settings → API Keys.";
		return { verdict: "missing_ingest", message };
	}
	// 200 (accepted, zero spans), 503 (capture_disabled — the scope gate at
	// :207 already passed by the time the handler reaches the NATS check), or
	// anything else we did not anticipate: none of these say "missing scope",
	// so none of them block. Only an explicit 403 does.
	if (res.status === 200 || res.status === 503) return { verdict: "ok" };
	return { verdict: "undetermined", status: res.status };
}

export type ChatScopeCheck =
	| { verdict: "ok" }
	| { verdict: "missing_chat"; message: string }
	| { verdict: "undetermined"; status: number };

/**
 * Probe the `chat` scope with a dry, empty `POST /v1/messages`.
 *
 * `{}` has no `model`, so the handler refuses it with 400 `invalid_request`
 * AFTER the scope gate and BEFORE the rate limiter, the monthly quota, the
 * audit publish and the BYOK lookup — nothing is dispatched, metered or
 * ledgered. A 403 is therefore the scope gate and nothing else.
 *
 * Same posture as {@link checkIngestScope}: only an explicit 403 blocks. A 404
 * means the gateway predates `GWY-47` and does not serve `/v1/messages` at all
 * — reported as undetermined so the caller can say so, never as a scope
 * failure, because those need different fixes (mint a key vs upgrade the
 * gateway).
 */
export async function checkChatScope(
	gateway: string,
	apiKey: string,
	fetchImpl: typeof fetch = fetch,
): Promise<ChatScopeCheck> {
	const base = gateway.replace(/\/$/, "");
	let res: Response;
	try {
		res = await fetchImpl(`${base}/v1/messages`, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${apiKey}`,
				"content-type": "application/json",
			},
			body: "{}",
		});
	} catch {
		return { verdict: "undetermined", status: 0 };
	}
	if (res.status === 403) {
		const body = await res.json().catch(() => ({}) as Record<string, unknown>);
		const nested = (body as { error?: { message?: string } }).error;
		const message: string =
			typeof nested === "object" && typeof nested?.message === "string"
				? nested.message
				: "This API key is not scoped for completions. It needs the `chat` scope; mint a new key with it in Settings → API Keys.";
		return { verdict: "missing_chat", message };
	}
	// 400 is the expected answer: the scope gate passed and the empty body was
	// refused after it. Anything else says nothing about the scope.
	if (res.status === 400) return { verdict: "ok" };
	return { verdict: "undetermined", status: res.status };
}

export interface SettingsMerge {
	/** Full file content to write, pretty-printed. */
	content: string;
	/** Env keys newly written. */
	written: string[];
	/** Env keys that already existed and were left untouched. */
	skipped: string[];
}

/** Indentation used by the existing file, or the default for a new one. */
function detectIndent(raw: string): string {
	const m = raw.match(/\n([ \t]+)\S/);
	return m?.[1] ?? "  ";
}

/**
 * Merge `envBlock` into `settings.json`'s `env` object.
 *
 * Never overwrites an existing key. `existingRaw` is `undefined` when the
 * file does not exist yet. Throws with a message naming the file when
 * `existingRaw` is not valid JSON — merging into a file we cannot parse would
 * silently discard whatever else it held.
 */
export function mergeClaudeSettings(
	existingRaw: string | undefined,
	envBlock: Record<string, string>,
	displayPath: string,
): SettingsMerge {
	let settings: Record<string, unknown> = {};
	if (existingRaw !== undefined && existingRaw.trim().length > 0) {
		try {
			settings = JSON.parse(existingRaw) as Record<string, unknown>;
		} catch (err) {
			throw new Error(
				`${displayPath} is not valid JSON (${(err as Error).message}) — fix or remove it before running \`tlane init claude-code\`.`,
			);
		}
		if (
			typeof settings !== "object" ||
			settings === null ||
			Array.isArray(settings)
		) {
			throw new Error(
				`${displayPath} does not contain a JSON object at its top level.`,
			);
		}
	}

	const env = { ...((settings.env as Record<string, string>) ?? {}) };
	const written: string[] = [];
	const skipped: string[] = [];
	for (const [k, v] of Object.entries(envBlock)) {
		if (Object.hasOwn(env, k)) {
			skipped.push(k);
		} else {
			env[k] = v;
			written.push(k);
		}
	}
	settings.env = env;

	const indent = existingRaw ? detectIndent(existingRaw) : "  ";
	const content = `${JSON.stringify(settings, null, indent)}\n`;
	return { content, written, skipped };
}

/** Resolve the target settings file: `~/.claude/settings.json` or `./.claude/settings.json`. */
export function settingsPath(project: boolean, cwd = process.cwd()): string {
	return project
		? join(cwd, ".claude", "settings.json")
		: join(homedir(), ".claude", "settings.json");
}

/** Read the target file if it exists, else `undefined`. Pure I/O, kept tiny and separate so the merge logic above stays a pure function. */
export function readIfExists(path: string): string | undefined {
	return existsSync(path) ? readFileSync(path, "utf8") : undefined;
}

/** Write `content` to `path`, creating parent directories as needed. */
export function writeSettings(path: string, content: string): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, content, "utf8");
}
