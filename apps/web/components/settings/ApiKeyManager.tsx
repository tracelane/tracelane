"use client";
import { fmtCount, fmtUsd } from "@/lib/metrics/format";

import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";

/**
 * ApiKeyManager — self-service tlane_* API key management UI.
 *
 * Lists active keys (prefix + name + dates), creates new keys, revokes keys.
 * The raw key is shown exactly once after creation in a copy-and-dismiss dialog.
 *
 * Pain-points: PP-G1 (developer onboarding), PP-G5 (BYOK key management).
 */

import { Modal } from "@/components/Modal";
import { apiFetch, apiFetchRaw } from "@/lib/api-fetch";
import { absoluteDate, formatDateTimeUtc } from "@/lib/format-date";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ObjectSurface } from "@tracelanedev/ui";
import { Button, Toast, usePeek } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import { KeyEditDrawer } from "./KeyEditDrawer";

export interface ApiKeyRow {
	id: string;
	name: string;
	keyPrefix: string;
	createdAt: string;
	lastUsedAt: string | null;
	/** WorkOS user id of the minter (null for pre-0011 keys → rendered "—"). */
	mintedBy?: string | null;
	/**
	 * A13. `null` means the key was minted BEFORE scopes existed and carries the
	 * full API surface — rendered as "Full access (legacy)" rather than as an
	 * empty list, because "no scopes" and "all scopes" are opposite meanings and
	 * showing a blank cell for the permissive one would be dangerously wrong.
	 */
	scope?: string[] | null;
	/** A13. `null` = never expires. */
	expiresAt?: string | null;
	/**
	 * GWY-43. Monthly USD ceiling for this key; `null` = uncapped.
	 *
	 * The union is not laziness. The LIST reads the Postgres `numeric` column,
	 * which the driver hands back as a STRING ("50.0000"); the create response
	 * echoes the value the gateway validated, which is a JSON NUMBER. Both reach
	 * this type, so both are declared — `formatBudget` normalises them.
	 */
	budgetUsdMonthly?: string | number | null;
	/** GWY-43. Requests/min ceiling for this key; `null` = the plan limit only. */
	rateLimitRpm?: number | null;
	/**
	 * BILL-01 A3 / SET-38. The window `budgetUsdMonthly` applies to — the column
	 * name is historical; a `daily` key's budget is per day.
	 */
	budgetReset?: "daily" | "weekly" | "monthly";
	/** BILL-01 A3. Anomaly-triggered freeze opted in for this key. */
	velocityBreaker?: boolean;
	/** Scheduled retirement of a rotated key, in UTC. */
	revokedAt?: string | null;
}

/**
 * Who is looking at the key list — passed down from the server page's session.
 * UI gating only: the gateway re-decides every edit, and is authoritative.
 */
export interface KeyViewer {
	/** WorkOS role slug (`owner` / `admin` / `member` / `viewer`), or `null`. */
	role: string | null;
	/** WorkOS user id — compared with a key's `mintedBy`. */
	userId: string;
}

/**
 * SET-38 §2 — may this viewer edit this key's limits? Mirrors the gateway's
 * `key_editor` (`crates/gateway/src/key_routes.rs`) for a dashboard session:
 * an owner (or WorkOS `admin`) may edit any key; a member only a key they minted;
 * a viewer, or a session with no recognised role, none. Fail-closed on an
 * unknown role, exactly like the gateway.
 */
export function canEditKeyLimits(viewer: KeyViewer, row: ApiKeyRow): boolean {
	if (viewer.role === "owner" || viewer.role === "admin") return true;
	if (viewer.role === "member") {
		return row.mintedBy != null && row.mintedBy === viewer.userId;
	}
	return false;
}

/** The closed scope vocabulary, mirrored from `tracelane_shared::api_scope`. */
const SCOPES: { value: string; label: string; hint: string }[] = [
	{
		value: "chat",
		label: "Chat",
		hint: "Send completions through the gateway",
	},
	{
		value: "read",
		label: "Read",
		hint: "Read traces, sessions and the audit ledger",
	},
	{
		value: "ingest",
		label: "Ingest",
		hint: "Send traces from an SDK (OTLP)",
	},
	{
		value: "admin",
		label: "Admin",
		hint: "Manage keys, providers and settings",
	},
];

/** Human label for a key's capability. */
function scopeLabel(scope: string[] | null | undefined): string {
	if (scope == null) return "Full access (legacy)";
	if (scope.length === 0) return "No access";
	return scope
		.map((v) => SCOPES.find((s) => s.value === v)?.label ?? v)
		.join(" · ");
}

/**
 * The monthly USD ceiling, formatted. Accepts the `numeric`-as-string the list
 * returns and the JSON number the create response echoes; anything that will not
 * parse renders as no cap, which matches the gateway — `db::api_keys` filters a
 * budget it cannot parse down to `None` rather than treating it as zero.
 */
/** The budget's reset window as a suffix (B-586: this read `/mo` for every key). */
const BUDGET_SUFFIX = {
	daily: "/day",
	weekly: "/week",
	monthly: "/mo",
} as const;

function formatBudget(
	v: string | number | null | undefined,
	reset: ApiKeyRow["budgetReset"],
): string | null {
	if (v == null) return null;
	const n = typeof v === "number" ? v : Number.parseFloat(v);
	return Number.isFinite(n) && n > 0
		? `${fmtUsd(n)}${BUDGET_SUFFIX[reset ?? "monthly"]}`
		: null;
}

/**
 * The key's own ceilings as one label, or `null` when it carries neither.
 *
 * Both are shown together because they answer one question — "what is this key
 * allowed to do?" — and because a key with no ceilings must read as *no
 * ceilings*, not as a blank cell. Same reasoning as the legacy-scope cell above.
 */
function limitsLabel(key: ApiKeyRow): string | null {
	const parts: string[] = [];
	const budget = formatBudget(key.budgetUsdMonthly, key.budgetReset);
	if (budget) parts.push(budget);
	if (key.rateLimitRpm != null && key.rateLimitRpm > 0) {
		parts.push(`${key.rateLimitRpm} req/min`);
	}
	return parts.length > 0 ? parts.join(" · ") : null;
}

/**
 * A numeric form field that is legitimately allowed to be empty. Blank, or
 * anything that does not parse to a finite number, is `null` = "not set" —
 * never `NaN`, which `JSON.stringify` would quietly write as `null` in the
 * request body and the server would read as a deliberate "no cap".
 */
function optionalNumber(raw: string): number | null {
	const t = raw.trim();
	if (t === "") return null;
	const n = Number(t);
	return Number.isFinite(n) ? n : null;
}

/** Is this key past its expiry? Display-only — the gateway is the real gate. */
function isExpired(expiresAt: string | null | undefined): boolean {
	if (!expiresAt) return false;
	const t = new Date(expiresAt).getTime();
	return Number.isFinite(t) && t <= Date.now();
}

/**
 * Idle hint for a key that has never been used. A key >7 days old with no
 * last-used is likely dead → a gentle "consider revoking"; a fresh key just
 * hasn't been used yet. Idle ≠ compromised — never imply the key is unsafe.
 */
function idleHint(createdAt: string, lastUsedAt: string | null): string | null {
	if (lastUsedAt) return null;
	const ageMs = Date.now() - new Date(createdAt).getTime();
	if (!Number.isFinite(ageMs)) return null;
	return ageMs > 7 * 86_400_000 ? "unused — consider revoking" : "unused (new)";
}

/**
 * The per-key ceilings, in one column.
 *
 * They live together because they answer one question — what is this key
 * allowed to spend and how fast — and because the column exists at all for a
 * reason worth stating: both are ENFORCED by the gateway (402 and 429), and a
 * limit the customer cannot see is one they cannot trust. Until GWY-43 the
 * budget column was writable only by hand-written SQL and readable nowhere.
 */
function LimitsCell({
	row,
	flash = false,
}: { row: ApiKeyRow; flash?: boolean }) {
	const label = limitsLabel(row);
	return (
		<TD
			className={`py-2 pr-3 text-xs ${flash ? "animate-pulse bg-surface-2" : ""}`}
			style={{ animationIterationCount: 1 }}
		>
			{label ? (
				<span
					className="text-ink-2"
					title="The budget is a hard stop (402 until its selected window resets); the rate limit returns 429 and narrows the workspace plan limit for this key."
				>
					{label}
				</span>
			) : (
				<span
					className="text-ink-3"
					title="No per-key ceilings — this key is bounded only by your workspace's plan limits."
				>
					None
				</span>
			)}
		</TD>
	);
}

interface CreateResult extends ApiKeyRow {
	rawKey: string;
	oldKeyRevokedAt?: string;
}

async function fetchKeys(): Promise<ApiKeyRow[]> {
	return apiFetch<ApiKeyRow[]>("/api/settings/api-keys");
}

export interface CreateKeyInput {
	name: string;
	scope: string[];
	expiresAt: string | null;
	/** GWY-43. `null` = no cap. */
	budgetUsdMonthly: number | null;
	/** GWY-43. `null` = inherit the workspace plan limit. */
	rateLimitRpm: number | null;
}

async function createKey(input: CreateKeyInput): Promise<CreateResult> {
	const res = await apiFetchRaw("/api/settings/api-keys", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			name: input.name,
			scope: input.scope,
			...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
			// Sent only when set. Omitted means "no cap", and JSON.stringify turns a
			// NaN into `null`, so an unparseable field must never reach the body —
			// it would read as a deliberate "uncapped" rather than as a mistake.
			...(input.budgetUsdMonthly != null
				? { budgetUsdMonthly: input.budgetUsdMonthly }
				: {}),
			...(input.rateLimitRpm != null
				? { rateLimitRpm: input.rateLimitRpm }
				: {}),
		}),
	});
	if (!res.ok) {
		// The gateway 400s with a message naming the bad scope or a past expiry,
		// and the proxy now preserves it. Surfacing `HTTP 400` instead would throw
		// away the only part the user can act on.
		const body = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(body.error ?? `HTTP ${res.status}`);
	}
	return res.json() as Promise<CreateResult>;
}

async function revokeKey(id: string): Promise<void> {
	const res = await apiFetchRaw(
		`/api/settings/api-keys/${encodeURIComponent(id)}`,
		{
			method: "DELETE",
		},
	);
	if (!res.ok) {
		// The proxy now answers with a reason (owner-only, not found, unchanged);
		// `HTTP 403` alone would throw that away.
		const body = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(body.error ?? `HTTP ${res.status}`);
	}
}

function CopyButton({ text }: { text: string }) {
	const [copied, setCopied] = useState(false);

	const copy = async () => {
		await navigator.clipboard.writeText(text);
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	};

	return (
		<Button
			variant="bare"
			type="button"
			onClick={copy}
			className="text-xs px-2 py-1 rounded border border-line text-ink-2 hover:text-ink hover:border-ink-3 transition-colors"
		>
			{copied ? "Copied!" : "Copy"}
		</Button>
	);
}

function NewKeyModal({
	rawKey,
	name,
	scope,
	revokedAt,
	onDone,
}: {
	rawKey: string;
	name: string;
	scope: string[] | null | undefined;
	revokedAt?: string | null;
	onDone: () => void;
}) {
	return (
		// `dismissable={false}`: this dialog shows the raw API key exactly once and
		// the server cannot re-issue it — a stray Escape would destroy it.
		<Modal
			title="API key created"
			titleAside={
				// `--warn-soft` is the named soft fill; `bg-warn/10` was a 10% wash of the
				// FILL token over whatever is behind the modal header, which is a
				// different colour in each theme and in neither case a chosen one.
				<span className="rounded border border-warn/20 bg-warn-soft px-2 py-0.5 text-xs text-warn-ink">
					Copy now — shown once
				</span>
			}
			description={name}
			onClose={onDone}
			width="lg"
			dismissable={false}
		>
			<div className="rounded-card bg-bg border border-line p-3 flex items-center justify-between gap-3">
				<code className="text-xs font-mono text-action-ink break-all">
					{rawKey}
				</code>
				<CopyButton text={rawKey} />
			</div>

			{/*
			 * WHAT THIS KEY CAN DO, shown at the one moment it is both known and
			 * still cheaply revocable. Its absence is how a key minted as
			 * "read-only" went out able to spend provider budget: the dialog
			 * pre-granted three scopes and nothing afterwards ever contradicted
			 * the operator's belief about what they had made.
			 *
			 * Chat is called out by name because it is the scope with a bill
			 * attached — the others cost visibility, this one costs money.
			 */}
			<div className="rounded-card border border-line p-3">
				<p className="text-2xs text-ink-2 mb-1.5">This key can:</p>
				<p className="text-xs text-ink">{scopeLabel(scope)}</p>
				{Array.isArray(scope) && scope.includes("chat") && (
					<p className="text-2xs text-warn-ink mt-1.5">
						Includes <strong>Chat</strong> — this key can send completions
						through the gateway and spend your provider budget. Revoke it now if
						that was not intended.
					</p>
				)}
				{scope == null && (
					<p className="text-2xs text-warn-ink mt-1.5">
						Legacy full-surface key — no scope recorded, so every surface is
						allowed.
					</p>
				)}
			</div>

			<p className="text-2xs text-ink-2">
				{revokedAt && (
					<>
						The old key is scheduled to stop working at{" "}
						{formatDateTimeUtc(revokedAt)}. Its existing expiry still applies.
						Update your agents with the successor shown above before then.{" "}
					</>
				)}
				Store this key in your secrets manager — this is the only time it's
				shown. We keep only a one-way verifier digest (HMAC + Argon2id), never
				the key itself; if you lose it, revoke and create a new one.
			</p>

			<div className="flex justify-end pt-1">
				<Button
					variant="bare"
					type="button"
					onClick={onDone}
					className="px-4 py-2 rounded text-sm bg-surface-2 text-ink hover:bg-surface-3 transition-colors"
				>
					I&apos;ve saved it
				</Button>
			</div>
		</Modal>
	);
}

// Exported for `api-key-scope-default.test.tsx`, which asserts against the
// RENDERED MARKUP that no scope arrives pre-granted. Testing the state array
// would pass while the checkboxes said otherwise (TRAPS §34).
export function CreateKeyDialog({
	onClose,
	onCreate,
	pending,
	error,
}: {
	onClose: () => void;
	onCreate: (input: CreateKeyInput) => void;
	pending: boolean;
	error: Error | null;
}) {
	const [name, setName] = useState("");
	// A13. Default = chat + read + ingest, NOT all four. The mint default at the
	// API is full-surface for backwards compatibility with existing callers, but a
	// human choosing in this dialog should be offered least-privilege — `admin`
	// lets a key mint further keys, which is the one capability worth an explicit
	// tick.
	//
	// GWY-41 added `ingest` to the default deliberately: the key someone mints in
	// their first five minutes is the key they paste into their app, and an app
	// both calls models and reports its traces. Leaving it off would mean the SDK
	// quickstart 403s for every new user, with the fix three screens away.
	// Unticking it is still one click for anyone who wants a chat-only key.
	// NOTHING PRE-CHECKED, and this is a deliberate reversal.
	//
	// This defaulted to ["chat", "read", "ingest"], so minting a READ-ONLY key
	// required noticing two boxes were already ticked and un-ticking them. The
	// founder minted a key intending read-only, got one that completed a real
	// Anthropic call, and only found out because a proof that needed a
	// non-chat-capable key kept succeeding.
	//
	// A credential dialog whose default grants the MOST is a default that fails
	// OPEN: the quiet path — open, name it, click Create — hands out chat (which
	// spends provider budget) and ingest. Least privilege says the quiet path must
	// grant nothing, and the form already refuses an empty scope with "Pick at
	// least one", so this costs one deliberate click and buys an explicit choice.
	const [scope, setScope] = useState<string[]>([]);
	const [expiresAt, setExpiresAt] = useState("");
	// GWY-43. Both limits are held as the raw input STRING and parsed once on
	// submit: "" is a real, meaningful value here (no cap), and coercing the box
	// to a number would make an empty field indistinguishable from a typed 0.
	const [budget, setBudget] = useState("");
	const [rateLimit, setRateLimit] = useState("");
	const toggle = (v: string) =>
		setScope((cur) =>
			cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v],
		);

	return (
		// `lg`, not the default `md`: GWY-43 added two more field groups, each with
		// the copy that states what happens AT the limit. At `md` the form ran past
		// a 768px viewport, and this Modal centres its panel — an overflowing panel
		// clips at the TOP, hiding the key-name field rather than the buttons.
		<Modal title="Create API key" onClose={onClose} width="lg">
			<form
				onSubmit={(e) => {
					e.preventDefault();
					if (name.trim() && !pending && scope.length > 0) {
						onCreate({
							name: name.trim(),
							scope,
							// <input type="datetime-local"> yields local wall-clock with
							// no zone. Send an explicit UTC instant rather than a naive
							// string — the gateway parses RFC3339 strictly, and a naive
							// value is the timestamp bug this repo has hit before.
							expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
							// `optionalNumber` returns null for blank AND for anything that
							// will not parse, so a half-typed box cannot be sent as an
							// unintended "no cap". The gateway validates the range.
							budgetUsdMonthly: optionalNumber(budget),
							rateLimitRpm: optionalNumber(rateLimit),
						});
					}
				}}
				className="space-y-3"
			>
				<div>
					<label
						htmlFor="key-name"
						className="text-xs font-medium text-ink-2 block mb-1"
					>
						Key name
					</label>
					<input
						id="key-name"
						type="text"
						value={name}
						onChange={(e) => setName(e.target.value)}
						placeholder="e.g. prod-agent, ci-runner"
						disabled={pending}
						className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring disabled:opacity-50"
						required
					/>
				</div>
				<fieldset className="space-y-1.5">
					<legend className="text-xs font-medium text-ink-2 mb-1">
						Scope — what this key may do
					</legend>
					{SCOPES.map((sc) => (
						<label
							key={sc.value}
							className="flex items-start gap-2 text-xs text-ink cursor-pointer"
						>
							<input
								type="checkbox"
								checked={scope.includes(sc.value)}
								onChange={() => toggle(sc.value)}
								disabled={pending}
								className="mt-0.5"
							/>
							<span>
								<span className="font-medium">{sc.label}</span>
								<span className="text-ink-2"> — {sc.hint}</span>
							</span>
						</label>
					))}
					{scope.length === 0 && (
						<p className="text-2xs text-danger-ink">
							Pick at least one — a key with no scope can do nothing.
						</p>
					)}
				</fieldset>

				<div>
					<label
						htmlFor="key-expires"
						className="text-xs font-medium text-ink-2 block mb-1"
					>
						Expires <span className="text-ink-3">(optional)</span>
					</label>
					<input
						id="key-expires"
						type="datetime-local"
						value={expiresAt}
						onChange={(e) => setExpiresAt(e.target.value)}
						disabled={pending}
						className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring disabled:opacity-50"
					/>
					<p className="text-2xs text-ink-3 mt-1">
						Leave blank for a key that never expires. Times are your local zone;
						the key expires at that instant in UTC.
					</p>
				</div>

				<div className="grid gap-3 sm:grid-cols-2">
					<div>
						<label
							htmlFor="key-budget"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							Monthly budget (USD){" "}
							<span className="text-ink-3">(optional)</span>
						</label>
						<input
							id="key-budget"
							type="number"
							inputMode="decimal"
							min="0.01"
							step="0.01"
							value={budget}
							onChange={(e) => setBudget(e.target.value)}
							placeholder="no limit"
							disabled={pending}
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring disabled:opacity-50"
						/>
						{/* Says what the code does and no more. The gateway checks this
						    before it decrypts a provider credential and returns 402
						    `key_budget_exceeded` with a `resets_at` — a stop, not a
						    throttle, which is exactly why it is NOT a 429: a 429 tells
						    every OpenAI-shaped client to retry into a wall
						    (server.rs, Step 2c). */}
						<p className="text-2xs text-ink-3 mt-1">
							A hard stop, not a throttle. Once this key&apos;s recorded spend
							for the month reaches the cap, <code>/v1/chat/completions</code>{" "}
							returns <strong>402</strong> for this key until the month rolls
							over — retrying does not help. Spend comes from each
							request&apos;s recorded cost, so a model we have no published
							price for adds nothing to the total. Leave blank for no limit.
						</p>
					</div>

					<div>
						<label
							htmlFor="key-rpm"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							Rate limit (requests/min){" "}
							<span className="text-ink-3">(optional)</span>
						</label>
						<input
							id="key-rpm"
							type="number"
							inputMode="numeric"
							min="1"
							step="1"
							value={rateLimit}
							onChange={(e) => setRateLimit(e.target.value)}
							placeholder="workspace default"
							disabled={pending}
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring disabled:opacity-50"
						/>
						{/* The per-key bucket is checked AFTER the workspace bucket and
						    both must pass (`RateLimiter::check_scoped`), so this narrows
						    the workspace allowance for one credential — it never widens
						    it. The 429 body carries `retry_after_secs`; there is no
						    `Retry-After` HEADER on this response, so do not promise one. */}
						<p className="text-2xs text-ink-3 mt-1">
							Requests past this rate get <strong>429</strong> with the seconds
							to wait, and the key keeps working. Your workspace plan limit
							still applies on top — this only narrows it for this key. Leave
							blank to use the plan limit alone.
						</p>
					</div>
				</div>

				{/* Surface the create error inline — without this the request could
				    fail (e.g. gateway/DB 500) and the dialog would appear to do
				    nothing. */}
				{error && (
					<p
						role="alert"
						className="text-xs text-danger-ink bg-danger-soft border border-danger/30 rounded px-2 py-1.5"
					>
						{/* Claims ONLY what the code knows. The previous copy read
						    "…check that the workspace has API-key creation enabled",
						    which named a setting that DOES NOT EXIST anywhere in the
						    product — no entitlement flag, no column, no config key —
						    and told the user to retry a failure that was 100%
						    deterministic. It invented a plausible cause for an upstream
						    fault and sent the customer to look for it. `error.message`
						    is the gateway's own 4xx text when the request was the
						    problem, or a generic string when the fault was ours
						    (api-keys/route.ts:117-126); the UI cannot tell which, so it
						    must not assert either. */}
						Couldn&apos;t create the key: {error.message}
					</p>
				)}
				<div className="flex justify-end gap-2 pt-1">
					<Button
						variant="bare"
						type="button"
						onClick={onClose}
						disabled={pending}
						className="px-4 py-2 rounded text-sm border border-line text-ink-2 hover:bg-surface-2 transition-colors disabled:opacity-50"
					>
						Cancel
					</Button>
					<Button
						variant="bare"
						type="submit"
						disabled={!name.trim() || pending}
						className="px-4 py-2 rounded text-sm bg-action text-action-on hover:bg-action/90 disabled:opacity-40 transition-colors"
					>
						{pending ? "Creating…" : "Create"}
					</Button>
				</div>
			</form>
		</Modal>
	);
}

function RotateKeyDialog({
	row,
	onClose,
	onRotate,
	pending,
	error,
}: {
	row: ApiKeyRow;
	onClose: () => void;
	onRotate: (graceHours: number) => void;
	pending: boolean;
	error: Error | null;
}) {
	const [chosen, setChosen] = useState<string | null>(null);
	const policy = useQuery({
		queryKey: ["api-key-rotation-policy"],
		queryFn: () =>
			apiFetch<{ graceHours: number }>(
				"/api/settings/api-keys/rotation-policy",
			),
	});
	const grace = chosen ?? (policy.data ? String(policy.data.graceHours) : "");
	const hours = Number(grace);
	const valid =
		grace.trim() !== "" && Number.isSafeInteger(hours) && hours >= 0;
	return (
		<Modal
			title="Rotate API key"
			description={row.name}
			onClose={onClose}
			dismissable={!pending}
		>
			<p className="text-sm text-ink-2">
				The successor keeps this key&apos;s scope, limits and expiry. Copy it
				once, then update your agents during the grace period. Rotation requires
				a workspace owner.
			</p>
			<form
				onSubmit={(e) => {
					e.preventDefault();
					if (valid && !pending) onRotate(hours);
				}}
				className="space-y-3"
			>
				<label htmlFor="rotation-grace" className="block text-sm text-ink">
					Grace period (hours)
				</label>
				<input
					id="rotation-grace"
					type="number"
					min="0"
					step="1"
					value={grace}
					onChange={(e) => setChosen(e.target.value)}
					disabled={pending}
					className="w-full rounded border border-line bg-bg px-3 py-2 text-ink"
				/>
				<p className="text-xs text-ink-2">
					Zero retires the old key immediately. An earlier expiry still applies.
				</p>
				{policy.isLoading && (
					<p className="text-xs text-ink-2">Loading default grace period…</p>
				)}
				{policy.isError && (
					<p role="alert" className="text-xs text-danger-ink">
						Could not load the default. Enter a grace period to continue.
					</p>
				)}
				{error && (
					<p role="alert" className="text-xs text-danger-ink">
						Couldn&apos;t rotate the key: {error.message}
					</p>
				)}
				<div className="flex justify-end gap-2">
					<Button
						variant="bare"
						type="button"
						onClick={onClose}
						disabled={pending}
						className="rounded border border-line px-3 py-2 text-sm"
					>
						Cancel
					</Button>
					<Button
						variant="bare"
						type="submit"
						disabled={!valid || pending}
						className="rounded bg-action px-3 py-2 text-sm text-action-on disabled:opacity-40"
					>
						{pending ? "Rotating…" : "Rotate key"}
					</Button>
				</div>
			</form>
		</Modal>
	);
}

export function ApiKeyManager({
	viewer,
}: {
	viewer: KeyViewer;
}) {
	const qc = useQueryClient();
	const [keyId, setKeyId] = usePeek("key");
	const [notice, setNotice] = useState<string | null>(null);
	const [changed, setChanged] = useState<{
		id: string;
		fields: string[];
	} | null>(null);

	useEffect(() => {
		if (!changed) return;
		const timer = setTimeout(() => setChanged(null), 1600);
		return () => clearTimeout(timer);
	}, [changed]);
	const [showCreate, setShowCreate] = useState(false);
	const [newKey, setNewKey] = useState<CreateResult | null>(null);
	const [rotating, setRotating] = useState<ApiKeyRow | null>(null);

	const {
		data: keys = [],
		isLoading,
		isError,
	} = useQuery({
		queryKey: ["api-keys"],
		queryFn: fetchKeys,
		staleTime: 30_000,
	});

	const editing = keys.find((row) => row.id === keyId);
	useEffect(() => {
		if (keyId && !isLoading)
			document
				.getElementById(`key-${keyId}`)
				?.scrollIntoView?.({ block: "center" });
	}, [keyId, isLoading]);
	const createMutation = useMutation({
		mutationFn: createKey,
		onSuccess: (result) => {
			void qc.invalidateQueries({ queryKey: ["api-keys"] });
			setShowCreate(false);
			setNewKey(result);
		},
	});

	const revokeMutation = useMutation({
		mutationFn: revokeKey,
		onSuccess: () => void qc.invalidateQueries({ queryKey: ["api-keys"] }),
	});
	const rotationMutation = useMutation({
		mutationFn: async ({
			id,
			graceHours,
		}: { id: string; graceHours: number }) => {
			const res = await apiFetchRaw(
				`/api/settings/api-keys/${encodeURIComponent(id)}/rotate`,
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ graceHours }),
				},
			);
			if (!res.ok) {
				const body = (await res.json().catch(() => ({}))) as { error?: string };
				throw new Error(body.error ?? `HTTP ${res.status}`);
			}
			return res.json() as Promise<CreateResult>;
		},
		onSuccess: (result) => {
			void qc.invalidateQueries({ queryKey: ["api-keys"] });
			setRotating(null);
			setNewKey(result);
		},
	});

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-between gap-3">
				<div>
					<h2 className="text-sm font-semibold text-ink">API keys</h2>
					<p className="text-xs text-ink-2 mt-0.5">
						Keys authenticate agent traffic through the gateway. Use one key per
						environment.
					</p>
				</div>
				<Button
					variant="bare"
					type="button"
					onClick={() => {
						createMutation.reset(); // clear any stale error before reopening
						setShowCreate(true);
					}}
					className="px-3 py-1.5 rounded text-sm bg-action text-action-on hover:bg-action/90 transition-colors"
				>
					+ New key
				</Button>
			</div>

			{keyId && !isLoading && !isError && !editing && (
				<p role="alert">That key isn't in this workspace</p>
			)}
			{isLoading && (
				<p className="text-sm text-ink-2 animate-pulse">Loading…</p>
			)}
			{isError && (
				<p className="text-sm text-danger-ink">Failed to load API keys.</p>
			)}
			{revokeMutation.isError && (
				<p role="alert" className="text-sm text-danger-ink">
					Couldn&apos;t revoke the key: {revokeMutation.error.message}
				</p>
			)}

			{!isLoading && !isError && keys.length === 0 && (
				<div className="rounded-card border border-dashed border-line p-8 text-center">
					<p className="text-sm text-ink-2">No API keys yet.</p>
					<p className="text-xs text-ink-3 mt-1">
						Create one to start routing agent traffic through Tracelane.
					</p>
				</div>
			)}

			{keys.length > 0 && (
				<div className="overflow-x-auto rounded-card border border-line">
					<Table className="w-full text-left">
						<THead className="bg-surface text-xs text-ink-2">
							<TR>
								<TH className="py-1.5 px-3 font-medium">Name</TH>
								<TH className="py-1.5 pr-3 font-medium">Prefix</TH>
								<TH className="py-1.5 pr-3 font-medium">Scope</TH>
								<TH className="py-1.5 pr-3 font-medium">Expires</TH>
								<TH
									className="py-1.5 pr-3 font-medium"
									title="Per-key monthly spend cap and requests-per-minute cap, both enforced by the gateway."
								>
									Limits
								</TH>
								<TH className="py-1.5 pr-3 font-medium">Created</TH>
								<TH className="py-1.5 pr-3 font-medium">Created by</TH>
								<TH
									className="py-1.5 pr-3 font-medium"
									title="Refreshed when a key misses the auth cache, so it can lag real usage by up to 15 minutes."
								>
									Last used{" "}
									<span className="font-normal text-ink-3" aria-hidden="true">
										†
									</span>
								</TH>
								<TH className="py-1.5 pr-3 font-medium" />
								<TH className="px-3 py-2">
									<span className="sr-only">Object actions</span>
								</TH>
							</TR>
						</THead>
						<TBody>
							{keys.map((key) => (
								<ObjectSurface
									key={key.id}
									id={`key-${key.id}`}
									objectId={key.id}
									title={key.name}
									href={`/settings/api-keys?key=${encodeURIComponent(key.id)}`}
									fields={[
										{ label: "Prefix", value: key.keyPrefix },
										{ label: "Scope", value: scopeLabel(key.scope) },
										{
											label: "Budget",
											value:
												key.budgetUsdMonthly == null
													? "Not set"
													: fmtUsd(Number(key.budgetUsdMonthly)),
										},
										{
											label: "RPM",
											value:
												key.rateLimitRpm == null
													? "Not set"
													: fmtCount(key.rateLimitRpm),
										},
									]}
									actions={[
										{
											label: "Edit limits",
											disabled:
												!canEditKeyLimits(viewer, key) ||
												isExpired(key.expiresAt),
											onSelect: () => setKeyId(key.id),
										},
									]}
									className="border-t border-line last:border-0"
								>
									<TD
										className={`py-2 px-3 text-sm text-ink ${changed?.id === key.id && changed.fields.includes("name") ? "animate-pulse bg-surface-2" : ""}`}
										style={{ animationIterationCount: 1 }}
									>
										{key.name}
										{key.revokedAt && (
											<p className="text-xs text-warn-ink">
												Retires {formatDateTimeUtc(key.revokedAt)}
											</p>
										)}
									</TD>
									<TD className="py-2 pr-3 font-mono text-xs text-ink-2">
										tlane_{key.keyPrefix}…
									</TD>
									<TD
										className={`py-2 pr-3 text-xs ${changed?.id === key.id ? "animate-pulse bg-surface-2" : ""}`}
										style={{ animationIterationCount: 1 }}
									>
										{/* `null` scope is a LEGACY key with the full surface —
										    never render it as an empty list, which would read as
										    "no access" and is the opposite of the truth. */}
										<span
											className={
												key.scope == null ? "text-warn-ink" : "text-ink-2"
											}
											title={
												key.scope == null
													? "Minted before scopes existed — carries the full API surface. Use Edit limits to narrow it in place."
													: undefined
											}
										>
											{scopeLabel(key.scope)}
										</span>
									</TD>
									<TD
										className={`py-2 pr-3 text-xs ${changed?.id === key.id ? "animate-pulse bg-surface-2" : ""}`}
										style={{ animationIterationCount: 1 }}
									>
										{key.expiresAt ? (
											<span
												className={
													isExpired(key.expiresAt)
														? "text-danger-ink"
														: "text-ink-2"
												}
											>
												{absoluteDate(key.expiresAt)}
												{isExpired(key.expiresAt) ? " (expired)" : ""}
											</span>
										) : (
											<span className="text-ink-3">Never</span>
										)}
									</TD>
									<LimitsCell
										row={key}
										flash={
											changed?.id === key.id &&
											changed.fields.some((f) =>
												[
													"budget_usd_monthly",
													"budget_reset",
													"rate_limit_rpm",
												].includes(f),
											)
										}
									/>
									<TD className="py-2 pr-3 text-xs text-ink-2">
										{absoluteDate(key.createdAt)}
									</TD>
									<TD className="py-2 pr-3 font-mono text-xs text-ink-3">
										{key.mintedBy ? `${key.mintedBy.slice(0, 14)}…` : "—"}
									</TD>
									<TD className="py-2 pr-3 text-xs text-ink-2">
										{key.lastUsedAt ? (
											absoluteDate(key.lastUsedAt)
										) : (
											<span
												title={idleHint(key.createdAt, key.lastUsedAt) ?? ""}
												className="text-ink-3"
											>
												{idleHint(key.createdAt, key.lastUsedAt) ?? "Never"}
											</span>
										)}
									</TD>
									<TD className="py-2 pr-3">
										{canEditKeyLimits(viewer, key) &&
											!isExpired(key.expiresAt) && (
												<Button size="sm" onClick={() => setKeyId(key.id)}>
													Edit limits
												</Button>
											)}
										<Button
											variant="bare"
											type="button"
											disabled={!!key.revokedAt || isExpired(key.expiresAt)}
											onClick={() => {
												rotationMutation.reset();
												setRotating(key);
											}}
											className="mr-2 rounded border border-line px-2 py-1 text-xs text-ink-2 disabled:opacity-40"
										>
											Rotate
										</Button>
										<Button
											variant="bare"
											type="button"
											onClick={() => {
												if (
													window.confirm(
														// B-586 (SET-38 B6): revoke now goes THROUGH THE
														// GATEWAY, which clears its own auth cache in the same
														// step, so the key's NEXT request is refused. Until then
														// this read "within 60 seconds", because the revoke was a
														// dashboard database write the gateway's 60 s cache never
														// saw. Requests already admitted still finish — hence
														// "next request", never "immediately".
														`Revoke "${key.name}"? The key stops working on its next request — any agent still using it will start failing authentication. This cannot be undone.`,
													)
												) {
													revokeMutation.mutate(key.id);
												}
											}}
											className="text-xs px-2 py-1 rounded border border-danger text-danger-ink hover:bg-danger-soft transition-colors"
										>
											Revoke
										</Button>
									</TD>
								</ObjectSurface>
							))}
						</TBody>
					</Table>
					<p className="px-4 pb-3 pt-2 text-2xs text-ink-3">
						† <strong>Last used</strong> is refreshed when a key misses the auth
						cache, so it can lag real usage by up to 15 minutes. A key used
						seconds ago may still read as older. Treat it as a staleness signal,
						not an audit trail — the audit ledger is authoritative.
					</p>
				</div>
			)}

			{editing && canEditKeyLimits(viewer, editing) && (
				<KeyEditDrawer
					key={editing.id}
					row={editing}
					onClose={() => setKeyId(null)}
					onSaved={(updated, fields) => {
						qc.setQueryData<ApiKeyRow[]>(["api-keys"], (old) =>
							old?.map((row) =>
								row.id === updated.id ? { ...row, ...updated } : row,
							),
						);
						setChanged({ id: updated.id, fields });
						setKeyId(null);
						setNotice("Limits updated — applies to this key's next request");
					}}
				/>
			)}
			<Toast message={notice} onDismiss={() => setNotice(null)} />
			{showCreate && (
				<CreateKeyDialog
					onClose={() => {
						setShowCreate(false);
						createMutation.reset();
					}}
					onCreate={(input) => createMutation.mutate(input)}
					pending={createMutation.isPending}
					error={createMutation.error}
				/>
			)}

			{newKey && (
				<NewKeyModal
					rawKey={newKey.rawKey}
					name={newKey.name}
					scope={newKey.scope}
					revokedAt={newKey.oldKeyRevokedAt}
					onDone={() => {
						setNewKey(null);
						createMutation.reset();
						rotationMutation.reset();
					}}
				/>
			)}
			{rotating && (
				<RotateKeyDialog
					row={rotating}
					onClose={() => {
						if (!rotationMutation.isPending) setRotating(null);
					}}
					onRotate={(graceHours) =>
						rotationMutation.mutate({ id: rotating.id, graceHours })
					}
					pending={rotationMutation.isPending}
					error={rotationMutation.error}
				/>
			)}
		</div>
	);
}
