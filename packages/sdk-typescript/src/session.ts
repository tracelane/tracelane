/**
 * Session (conversation) correlation for the Tracelane gateway.
 *
 * `/sessions` groups traces by `gen_ai.conversation.id`. There are exactly two
 * ways that id reaches Tracelane, and this module populates both:
 *
 * 1. **Gateway path** — an `x-conversation-id` request header on the call to
 *    `https://<gateway>/v1/chat/completions`. The gateway reads that header
 *    (falling back to `x-session-id`) and stamps it onto the span it records.
 * 2. **OTLP path** — the `gen_ai.conversation.id` span attribute, which the
 *    ingest OTLP decoder maps onto the same column.
 *
 * Until this module existed the read side was built but nothing in either SDK
 * could set the id, so `/sessions` stayed empty for every SDK user.
 *
 * @example Scoped to one conversation turn (safe under concurrency)
 * ```ts
 * import { withSession } from "@tracelanedev/sdk";
 *
 * await withSession("sess-42", () =>
 *   client.chat.completions.create({ model: "claude-sonnet-4-6", messages }),
 * );
 * ```
 *
 * @example No instrumentation — hand the header to any OpenAI-compatible client
 * ```ts
 * import { sessionHeaders } from "@tracelanedev/sdk";
 *
 * await client.chat.completions.create(
 *   { model: "claude-sonnet-4-6", messages },
 *   { headers: sessionHeaders("sess-42") },
 * );
 * ```
 */

import { AsyncLocalStorage } from "node:async_hooks";

/**
 * The header the gateway reads first.
 * Source of truth: `crates/gateway/src/server.rs:959-963`.
 */
export const CONVERSATION_ID_HEADER = "x-conversation-id";

/** The alias the gateway falls back to when {@link CONVERSATION_ID_HEADER} is absent. */
export const SESSION_ID_HEADER = "x-session-id";

/** The OTel span attribute the ingest OTLP decoder maps to the same column. */
export const CONVERSATION_ID_ATTRIBUTE = "gen_ai.conversation.id";

/**
 * Max length of a session id, in unicode scalar values.
 *
 * Mirrors the gateway's cap on the sibling customer-supplied
 * `x-business-reference` header (`crates/shared/src/span.rs`), so a value this
 * SDK accepts is a value the recorder stores. Over-long ids are rejected, never
 * truncated — a truncated id is a *wrong* id, and would silently split one
 * conversation into two.
 */
export const MAX_SESSION_ID_LENGTH = 256;

/** Header names that mean "a session id is already set", compared lowercased. */
const SESSION_HEADER_NAMES: readonly string[] = [
	CONVERSATION_ID_HEADER,
	SESSION_ID_HEADER,
];

const storage = new AsyncLocalStorage<string>();

/** Process-wide fallback set by {@link setSession}; `withSession` wins over it. */
let ambientSessionId: string | undefined;

/**
 * Validate and canonicalise a session id.
 *
 * Fails **CLOSED**: an id that the gateway could not carry on the wire throws
 * here, at the call the developer wrote, rather than being dropped in transit
 * and leaving `/sessions` mysteriously empty. Rejects the empty string,
 * anything longer than {@link MAX_SESSION_ID_LENGTH}, and any character outside
 * visible ASCII — which is exactly the set `HeaderValue::to_str()` accepts
 * gateway-side, and which also makes CR/LF header injection unrepresentable.
 *
 * @param raw - The candidate id. Surrounding whitespace is trimmed.
 * @returns The trimmed id.
 * @throws TypeError - If the id is not a non-empty, wire-safe string.
 */
export function normalizeSessionId(raw: string): string {
	if (typeof raw !== "string") {
		throw new TypeError(
			`Tracelane session id must be a string, received ${typeof raw}`,
		);
	}
	const trimmed = raw.trim();
	if (trimmed.length === 0) {
		throw new TypeError("Tracelane session id must not be empty");
	}
	const scalars = [...trimmed];
	if (scalars.length > MAX_SESSION_ID_LENGTH) {
		throw new TypeError(
			`Tracelane session id must be at most ${MAX_SESSION_ID_LENGTH} characters, received ${scalars.length} — ids are rejected rather than truncated, because a truncated id is a wrong id`,
		);
	}
	for (const ch of scalars) {
		const code = ch.codePointAt(0) ?? 0;
		if (code < 0x20 || code > 0x7e) {
			throw new TypeError(
				`Tracelane session id must be visible ASCII (U+0020..U+007E); found U+${code.toString(16).toUpperCase().padStart(4, "0")}. The gateway drops header values outside that range, so the session would be lost silently.`,
			);
		}
	}
	return trimmed;
}

/**
 * Run `fn` with `sessionId` as the active session.
 *
 * Backed by `AsyncLocalStorage`, so concurrent conversations never bleed into
 * each other — unlike {@link setSession}, which is process-wide.
 *
 * @param sessionId - The conversation id. Validated by {@link normalizeSessionId}.
 * @param fn - The work to run. Its return value (including a promise) is passed through.
 * @throws TypeError - If `sessionId` is not wire-safe. Fails CLOSED, before `fn` runs.
 */
export function withSession<T>(sessionId: string, fn: () => T): T {
	return storage.run(normalizeSessionId(sessionId), fn);
}

/**
 * Set the process-wide session id, for single-conversation scripts and CLIs.
 *
 * Prefer {@link withSession} in a server: this value is shared by every request
 * in the process. Pass `undefined` or `null` to clear it.
 *
 * @param sessionId - The conversation id, or `undefined`/`null` to clear.
 * @throws TypeError - If a non-null `sessionId` is not wire-safe. Fails CLOSED.
 */
export function setSession(sessionId: string | undefined | null): void {
	ambientSessionId =
		sessionId == null ? undefined : normalizeSessionId(sessionId);
}

/**
 * The session id that would be attached to a call made right now.
 *
 * @returns The `withSession` scope's id, else the {@link setSession} value, else `undefined`.
 */
export function getSession(): string | undefined {
	return storage.getStore() ?? ambientSessionId;
}

/**
 * The request headers that put a call into a session.
 *
 * Hand these to any OpenAI-compatible client — no Tracelane instrumentation
 * required. Returns an empty object when no session is active, so it is always
 * safe to spread.
 *
 * @param sessionId - An explicit id; defaults to the currently active session.
 * @returns `{ "x-conversation-id": id }`, or `{}` when no session is active.
 * @throws TypeError - If an explicit `sessionId` is not wire-safe. Fails CLOSED.
 */
export function sessionHeaders(sessionId?: string): Record<string, string> {
	const id =
		sessionId === undefined ? getSession() : normalizeSessionId(sessionId);
	return id === undefined ? {} : { [CONVERSATION_ID_HEADER]: id };
}

/**
 * Coerce any `HeadersLike` the OpenAI/Anthropic clients accept into a plain record.
 *
 * @returns The record, or `undefined` if the shape is unrecognised.
 */
function toHeaderRecord(
	existing: unknown,
): Record<string, unknown> | undefined {
	if (existing == null) return {};
	if (typeof Headers !== "undefined" && existing instanceof Headers) {
		return Object.fromEntries(existing.entries());
	}
	if (Array.isArray(existing)) {
		const out: Record<string, unknown> = {};
		for (const pair of existing) {
			if (Array.isArray(pair) && typeof pair[0] === "string") {
				out[pair[0]] = pair[1];
			}
		}
		return out;
	}
	if (typeof existing === "object") {
		// The vendor SDKs' internal `NullableHeaders` wraps a real `Headers`.
		const values = (existing as { values?: unknown }).values;
		if (typeof Headers !== "undefined" && values instanceof Headers) {
			return Object.fromEntries(values.entries());
		}
		return { ...(existing as Record<string, unknown>) };
	}
	return undefined;
}

/**
 * Merge the active session header into a request's existing headers.
 *
 * Fails **OPEN**: observability must never break the caller's LLM call, so an
 * unrecognised header shape yields `undefined` (leave the request alone) rather
 * than throwing. The span attribute still carries the session in that case.
 *
 * An explicitly-supplied `x-conversation-id`/`x-session-id` always wins over the
 * ambient session — the developer said what they meant.
 *
 * @param existing - Whatever the caller passed as `options.headers`.
 * @param sessionId - The already-validated active session id.
 * @returns The merged header record, or `undefined` to leave `existing` untouched.
 * @internal
 */
export function mergeSessionHeader(
	existing: unknown,
	sessionId: string,
): Record<string, unknown> | undefined {
	const record = toHeaderRecord(existing);
	if (record === undefined) return undefined;
	for (const name of Object.keys(record)) {
		if (SESSION_HEADER_NAMES.includes(name.toLowerCase())) return undefined;
	}
	record[CONVERSATION_ID_HEADER] = sessionId;
	return record;
}

/**
 * Attach the active session to an instrumented `create(body, options?)` call.
 *
 * Mutates `args` in place, adding the request-options argument if the caller
 * omitted it. A no-op when no session is active, so an un-sessioned call reaches
 * the vendor SDK byte-identical to an uninstrumented one.
 *
 * @param args - The argument array of the wrapped `create` call.
 * @returns The active session id, for stamping onto the span, or `undefined`.
 * @internal
 */
export function applySessionToArgs(args: unknown[]): string | undefined {
	const sessionId = getSession();
	if (sessionId === undefined) return undefined;

	const options = (args[1] ?? {}) as Record<string, unknown>;
	const merged = mergeSessionHeader(options.headers, sessionId);
	if (merged !== undefined) {
		args[1] = { ...options, headers: merged };
	}
	return sessionId;
}
