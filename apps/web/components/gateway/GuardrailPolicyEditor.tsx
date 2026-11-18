"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@tracelanedev/ui";
import { useEffect, useRef, useState } from "react";
import {
	Boundary,
	type ControlError,
	RefusalNote,
	controlRequest,
	useCan,
	useControlQuery,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

type Mode = "observe" | "redact" | "block";
type Terms = { denied_topics?: string[]; competitors?: string[] };
type TermLimits = { list_count: number; term_bytes: number };
type CustomAction = "observe" | "redact" | "block";
type CustomEntity = { name: string; pattern: string; action: CustomAction };
type CustomLimits = { custom_count: number; custom_pattern_bytes: number };
type Pii = {
	classes?: Record<string, string>;
	allowlist?: string[];
	custom?: CustomEntity[];
	[key: string]: unknown;
};
type RailRule = {
	enabled?: boolean;
	mode?: Mode;
	thresholds?: Record<string, number>;
	terms?: Terms;
	pii?: Pii;
	[key: string]: unknown;
};
type Policy = { rails: Record<string, RailRule> };
type RailView = {
	entitled: boolean;
	enabled: boolean;
	override: RailRule | null;
	default_behavior: {
		mode?: string;
		thresholds?: Record<string, number>;
		[key: string]: unknown;
	};
	plan_needed?: string;
};
type PolicyView = {
	scope: string;
	id: string;
	policy: Policy | null;
	effective: Record<string, RailView>;
	etag: string;
	can_edit: boolean;
};
const EMPTY_POLICY: Policy = { rails: {} };

const labels: Record<string, string> = {
	R1_cost: "Cost limits",
	R2_secrets_pii: "Secrets and personal data",
	R3_schema: "Response schema",
	R3_pinning: "Tool pinning",
	R4_trifecta: "Answer quality",
	R5_format: "Output format",
	R6_sysprompt_leak: "System prompt leaks",
	R7_topic_competitor: "Topic and competitor terms",
	R8_injection: "Prompt injection",
};
const thresholdLabels: Record<string, string> = {
	max_input_tokens: "Maximum input tokens",
	max_output_tokens: "Maximum output tokens",
	max_steps_per_run: "Maximum steps per run",
	max_identical_tool_calls: "Maximum identical tool calls",
	max_subagent_depth: "Maximum subagent depth",
	min_tokens: "Minimum matching tokens",
	score: "Minimum score",
};
const thresholdKeys: Record<string, string[]> = {
	R1_cost: [
		"max_input_tokens",
		"max_output_tokens",
		"max_steps_per_run",
		"max_identical_tool_calls",
		"max_subagent_depth",
	],
	R6_sysprompt_leak: ["min_tokens"],
	R8_injection: ["score"],
};
const redactRails = new Set(["R2_secrets_pii", "R6_sysprompt_leak"]); // gitleaks:allow — rail ids, not secrets
const TERMS_RAIL = "R7_topic_competitor";
const PII_RAIL = "R2_secrets_pii";
const CUSTOM_NAME = /^[a-z0-9_]{1,32}$/;
// The R2 classes the rail mode governs before a `pii` object exists (IP addresses are
// outside R2's default scope and stay off).
const BUILTIN_CLASSES = ["secrets", "email", "phone", "card", "ssn"];

/** Why a custom-pattern list would be refused by the gateway, or null. Pattern syntax is
 * the gateway's (Rust `regex`); it answers a bad pattern with `invalid_policy`. */
export function customListError(
	list: unknown,
	limits: CustomLimits | undefined,
): string | null {
	if (list === undefined) return null;
	if (!Array.isArray(list)) return "Custom patterns are not a list.";
	if (!limits) return "This gateway did not report custom pattern limits.";
	if (list.length > limits.custom_count)
		return `At most ${limits.custom_count} custom patterns.`;
	const names = new Set<string>();
	for (const item of list as CustomEntity[]) {
		if (!item || typeof item !== "object")
			return "A custom pattern is not valid.";
		if (!CUSTOM_NAME.test(item.name ?? ""))
			return "A pattern name uses 1–32 lowercase letters, digits or underscores.";
		if (names.has(item.name)) return "Pattern names must be unique.";
		names.add(item.name);
		if (!item.pattern) return "A custom pattern is empty.";
		if (utf8.encode(item.pattern).length > limits.custom_pattern_bytes)
			return `Each pattern can be at most ${limits.custom_pattern_bytes} bytes.`;
		if (!["observe", "redact", "block"].includes(item.action))
			return "A custom pattern needs an action.";
	}
	return null;
}
const termLists: { key: keyof Terms; label: string; hint: string }[] = [
	{
		key: "denied_topics",
		label: "Denied topics",
		hint: "One phrase per line. A match is recorded, or blocked in Block mode.",
	},
	{
		key: "competitors",
		label: "Competitor names",
		hint: "One name per line. A mention is recorded, or blocked in Block mode.",
	},
];
const utf8 = new TextEncoder();
// Mirrors the gateway's check (guardrail/policy.rs `Terms::valid`): control characters
// other than whitespace are refused.
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point
const CONTROL = /[\u0000-\u0008\u000e-\u001f\u007f-\u009f]/;

// Mirrors `char::is_alphanumeric` (Alphabetic or Numeric) in the gateway check.
const WORD = /[\p{Alphabetic}\p{N}]/u;
// An unpaired UTF-16 surrogate serialises to JSON the gateway cannot decode.
const LONE_SURROGATE =
	/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Lines of a textarea as a term list: trimmed, blank lines dropped. */
export function parseTermLines(text: string): string[] {
	return text
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line !== "");
}

/** Why a term list would be refused by the gateway, or null. */
export function termListError(
	list: unknown,
	limits: TermLimits | undefined,
): string | null {
	if (list === undefined) return null;
	if (!Array.isArray(list) || list.some((t) => typeof t !== "string"))
		return "A term list is not a list of text.";
	if (!limits) return "This gateway did not report term limits.";
	if (list.length > limits.list_count)
		return `A term list can hold at most ${limits.list_count} entries.`;
	for (const term of list as string[]) {
		if (term.trim() === "") return "A term list contains a blank entry.";
		if (utf8.encode(term).length > limits.term_bytes)
			return `Each term can be at most ${limits.term_bytes} bytes.`;
		if (CONTROL.test(term)) return "A term contains a control character.";
		if (!WORD.test(term))
			return "Each term needs at least one letter or digit.";
		if (LONE_SURROGATE.test(term)) return "A term contains a broken character.";
	}
	return null;
}

function CustomPatterns({
	title,
	value,
	disabled,
	onChange,
}: {
	title: string;
	value: CustomEntity[];
	disabled: boolean;
	onChange: (custom: CustomEntity[]) => void;
}) {
	const set = (i: number, change: Partial<CustomEntity>) =>
		onChange(value.map((c, j) => (j === i ? { ...c, ...change } : c)));
	return (
		<div className="space-y-2">
			<p className="text-xs text-ink-3">
				Custom patterns: your own regular expressions (Rust syntax), checked
				before the built-in detectors. Observe records a match, Redact replaces
				it before the model sees it, Block refuses the request. A pattern needs
				a bounded length, such as {"{1,40}"} instead of +, and a word boundary
				is written {"(?-u:\\b)"}.
			</p>
			{value.map((c, i) => (
				<div
					// biome-ignore lint/suspicious/noArrayIndexKey: rows have no stable id while a name is being typed
					key={i}
					className="grid gap-2 sm:grid-cols-[10rem_1fr_8rem_auto]"
				>
					<Field label={`${title} pattern ${i + 1} name`}>
						<input
							className={inputClass}
							disabled={disabled}
							value={c.name}
							onChange={(e) => set(i, { name: e.target.value })}
						/>
					</Field>
					<Field label={`${title} pattern ${i + 1} expression`}>
						<input
							className={inputClass}
							disabled={disabled}
							value={c.pattern}
							spellCheck={false}
							onChange={(e) => set(i, { pattern: e.target.value })}
						/>
					</Field>
					<Field label={`${title} pattern ${i + 1} action`}>
						<select
							className={inputClass}
							disabled={disabled}
							value={c.action}
							onChange={(e) =>
								set(i, { action: e.target.value as CustomAction })
							}
						>
							<option value="observe">Observe</option>
							<option value="redact">Redact</option>
							<option value="block">Block</option>
						</select>
					</Field>
					<Button
						size="sm"
						disabled={disabled}
						aria-label={`Remove ${title} pattern ${i + 1}`}
						onClick={() => onChange(value.filter((_, j) => j !== i))}
					>
						Remove
					</Button>
				</div>
			))}
			<Button
				size="sm"
				disabled={disabled}
				onClick={() =>
					onChange([...value, { name: "", pattern: "", action: "observe" }])
				}
			>
				Add custom pattern
			</Button>
		</div>
	);
}

function TermListField({
	label,
	hint,
	value,
	disabled,
	onChange,
}: {
	label: string;
	hint: string;
	value: string[];
	disabled: boolean;
	onChange: (terms: string[]) => void;
}) {
	// Local text keeps blank and trailing lines while typing; the policy holds the parsed list.
	const [text, setText] = useState(value.join("\n"));
	useEffect(() => {
		setText((current) =>
			JSON.stringify(parseTermLines(current)) === JSON.stringify(value)
				? current
				: value.join("\n"),
		);
	}, [value]);
	return (
		<Field label={label} hint={hint}>
			<textarea
				className={inputClass}
				rows={4}
				disabled={disabled}
				value={text}
				onChange={(e) => {
					setText(e.target.value);
					onChange(parseTermLines(e.target.value));
				}}
			/>
		</Field>
	);
}

function hidden(v: unknown): boolean {
	if (v === "[hidden]") return true;
	if (Array.isArray(v)) return v.some(hidden);
	return v !== null && typeof v === "object" && Object.values(v).some(hidden);
}

function formError(policy: Policy, view: PolicyView): string | null {
	if (hidden(policy) || hidden(view.effective))
		return "This policy contains a hidden value and cannot be edited safely here.";
	for (const [name, rule] of Object.entries(policy.rails)) {
		if (!view.effective[name])
			return "This policy contains a rail the gateway did not describe.";
		if (
			!view.effective[name].entitled &&
			JSON.stringify(rule) !== JSON.stringify(view.policy?.rails[name])
		)
			return "A locked rail cannot be changed here.";
		if (rule.mode === "redact" && !redactRails.has(name))
			return "Redact is not available for this rail.";
		if (rule.terms !== undefined) {
			if (name !== TERMS_RAIL)
				return "Term lists are only available for this rail.";
			if (
				rule.terms === null ||
				typeof rule.terms !== "object" ||
				Object.keys(rule.terms).some(
					(k) => k !== "denied_topics" && k !== "competitors",
				)
			)
				return "A term list is not valid.";
			const limits = view.effective[name].default_behavior.term_limits as
				| TermLimits
				| undefined;
			const termError =
				termListError(rule.terms.denied_topics, limits) ??
				termListError(rule.terms.competitors, limits);
			if (termError) return termError;
		}
		if (rule.pii?.custom !== undefined) {
			if (name !== PII_RAIL)
				return "Custom patterns are only available for this rail.";
			const customError = customListError(
				rule.pii.custom,
				view.effective[name].default_behavior.custom_limits as
					| CustomLimits
					| undefined,
			);
			if (customError) return customError;
		}
		for (const [key, value] of Object.entries(rule.thresholds ?? {})) {
			if (!thresholdKeys[name]?.includes(key) || !Number.isFinite(value))
				return "A threshold is not valid for this rail.";
			if (
				key === "score"
					? value < 0 || value > 1
					: !Number.isInteger(value) || value < 1 || value > 4294967295
			)
				return "A threshold is outside its allowed range.";
			if (
				key === "min_tokens" &&
				value >
					(view.effective[name].default_behavior.thresholds?.min_tokens ?? 0)
			)
				return "Minimum matching tokens exceeds the default limit.";
			if (
				name === "R1_cost" &&
				value > (view.effective[name].default_behavior.thresholds?.[key] ?? 0)
			)
				return "This threshold exceeds the built-in ceiling.";
		}
	}
	return null;
}

function GuardrailForm({
	view,
	allowed,
	reason,
	onReload,
}: {
	view: PolicyView;
	allowed: boolean;
	reason: string | null;
	onReload: () => Promise<PolicyView | null>;
}) {
	const original = view.policy ?? EMPTY_POLICY;
	const [policy, setPolicy] = useState<Policy>(original);
	const baseline = useRef({ policy: original, etag: view.etag });
	const [reloading, setReloading] = useState(false);
	const qc = useQueryClient();
	const save = useMutation<{ etag: string }, ControlError, Policy>({
		mutationFn: (draft) =>
			controlRequest("PUT", "guardrails/policy", draft, {
				"if-match": baseline.current.etag,
			}),
		onSuccess: async (response, draft) => {
			baseline.current = { policy: draft, etag: response.etag };
			setPolicy(draft);
			await qc.invalidateQueries({
				queryKey: ["gateway-control", "guardrails/policy"],
			});
		},
	});
	useEffect(() => {
		if (JSON.stringify(policy) === JSON.stringify(baseline.current.policy)) {
			baseline.current = { policy: original, etag: view.etag };
			setPolicy(original);
		}
	}, [original, policy, view.etag]);
	const remoteChanged = baseline.current.etag !== view.etag;
	const conflict = save.error?.status === 409;
	const changed = [
		...new Set([
			...Object.keys(baseline.current.policy.rails),
			...Object.keys(policy.rails),
		]),
	].filter(
		(name) =>
			JSON.stringify(baseline.current.policy.rails[name]) !==
			JSON.stringify(policy.rails[name]),
	).length;
	const invalid = formError(policy, view);
	const disabled =
		!allowed ||
		!view.can_edit ||
		save.isPending ||
		!!invalid ||
		remoteChanged ||
		conflict ||
		reloading;
	const disabledReason = !view.can_edit
		? "Your role cannot change guardrail policy."
		: reason;
	const patch = (name: string, change: Partial<RailRule>) =>
		setPolicy((p) => ({
			...p,
			rails: {
				...p.rails,
				[name]: {
					enabled: view.effective[name]?.enabled ?? true,
					mode: p.rails[name]
						? (p.rails[name].mode ?? "observe")
						: (view.effective[name]?.default_behavior.mode as Mode),
					...p.rails[name],
					...change,
				},
			},
		}));
	return (
		<div className="space-y-5">
			<Panel
				title="Guardrail policy"
				description="Overrides for this workspace. A rail without an override uses its built-in behavior."
			>
				{Object.keys(view.effective).length === 0 ? (
					<EmptyNote>No rails were returned by this gateway.</EmptyNote>
				) : null}
				{Object.entries(view.effective).map(([name, rail]) => {
					const title = labels[name] ?? name.replaceAll("_", " ");
					const rule = policy.rails[name];
					const locked = !rail.entitled;
					const rowDisabled = disabled || locked;
					const needsMode = !rule && rail.default_behavior.mode === "built_in";
					const keys = thresholdKeys[name] ?? [];
					return (
						<section
							key={name}
							className="space-y-3 border-t border-line pt-4"
							aria-label={title}
						>
							<div className="flex flex-wrap items-center justify-between gap-2">
								<h4 className="text-sm font-semibold text-ink">{title}</h4>
								<span className="text-xs text-ink-3">
									{locked
										? rail.plan_needed
											? `Requires ${rail.plan_needed}`
											: "Plan needed"
										: rule
											? "Workspace override"
											: "Built-in behavior"}
								</span>
							</div>
							{locked ? (
								<p className="text-xs text-ink-3">
									This rail is not included in the current plan.
								</p>
							) : null}
							<div className="grid gap-3 sm:grid-cols-2">
								<Field label={`${title} enabled`}>
									<input
										type="checkbox"
										disabled={rowDisabled || needsMode}
										checked={rule?.enabled ?? rail.enabled}
										onChange={(e) => patch(name, { enabled: e.target.checked })}
									/>
								</Field>
								<Field label={`${title} mode`}>
									<select
										className={inputClass}
										disabled={rowDisabled}
										value={
											rule
												? (rule.mode ?? "observe")
												: (rail.default_behavior.mode ?? "observe")
										}
										onChange={(e) =>
											patch(name, { mode: e.target.value as Mode })
										}
									>
										{needsMode ? (
											<option value="built_in">Built-in behavior</option>
										) : null}
										<option value="observe">Observe</option>
										{redactRails.has(name) ? (
											<option value="redact">Redact</option>
										) : null}
										<option value="block">Block</option>
									</select>
								</Field>
							</div>
							{needsMode ? (
								<p className="text-xs text-ink-3">
									Choose an override mode before changing this rail. Its
									built-in behavior may block requests.
								</p>
							) : null}
							{keys.length > 0 ? (
								<div className="grid gap-3 sm:grid-cols-2">
									{keys.map((key) => {
										const defaultValue =
											rail.default_behavior.thresholds?.[key];
										return (
											<Field
												key={key}
												label={`${title} ${thresholdLabels[key] ?? key}`}
												hint={
													defaultValue === undefined
														? "Blank uses the built-in behavior."
														: `Built-in value: ${defaultValue}`
												}
											>
												<input
													className={inputClass}
													type="number"
													min={key === "score" ? 0 : 1}
													max={
														key === "score"
															? 1
															: key === "min_tokens"
																? defaultValue
																: 4294967295
													}
													step={key === "score" ? "any" : 1}
													disabled={rowDisabled || needsMode}
													value={rule?.thresholds?.[key] ?? ""}
													onChange={(e) => {
														const thresholds = { ...rule?.thresholds };
														if (e.target.value === "") delete thresholds[key];
														else thresholds[key] = Number(e.target.value);
														patch(name, { thresholds });
													}}
												/>
											</Field>
										);
									})}
								</div>
							) : null}
							{name === PII_RAIL ? (
								<CustomPatterns
									title={title}
									value={rule?.pii?.custom ?? []}
									disabled={rowDisabled || needsMode}
									onChange={(custom) => {
										const { custom: _old, ...rest } = rule?.pii ?? {};
										// A first `pii` object takes over from the rail mode (the
										// gateway reads per-class actions once `pii` exists), so seed
										// every built-in class with the current mode: adding a pattern
										// must never weaken Block or Observe to the built-in Redact.
										const mode =
											rule?.mode ?? (rail.default_behavior.mode as Mode);
										const seeded =
											rule?.pii || mode === "redact"
												? {}
												: Object.fromEntries(
														BUILTIN_CLASSES.map((c) => [c, mode]),
													);
										const pii: Pii | undefined =
											custom.length > 0
												? { classes: seeded, ...rest, custom }
												: rule?.pii
													? { classes: {}, ...rest }
													: undefined;
										patch(name, { pii });
									}}
								/>
							) : null}
							{name === TERMS_RAIL ? (
								<div className="grid gap-3 sm:grid-cols-2">
									{termLists.map((list) => (
										<TermListField
											key={list.key}
											label={`${title} ${list.label.toLowerCase()}`}
											hint={list.hint}
											value={rule?.terms?.[list.key] ?? []}
											disabled={rowDisabled || needsMode}
											onChange={(terms) => {
												const next: Terms = {
													...rule?.terms,
													[list.key]: terms,
												};
												if (next[list.key]?.length === 0) delete next[list.key];
												patch(name, {
													terms:
														Object.keys(next).length > 0 ? next : undefined,
												});
											}}
										/>
									))}
								</div>
							) : null}
							<Button
								size="sm"
								disabled={rowDisabled || !rule}
								aria-label={`Reset ${title}`}
								onClick={() =>
									setPolicy((p) => {
										const rails = { ...p.rails };
										delete rails[name];
										return { ...p, rails };
									})
								}
							>
								Reset to built-in
							</Button>
						</section>
					);
				})}
			</Panel>
			{invalid ? (
				<p role="alert" className="text-sm text-danger-ink">
					{invalid}
				</p>
			) : null}
			{remoteChanged ? (
				<p role="alert" className="text-sm text-danger-ink">
					The policy changed while you were editing. Reload it before saving.
				</p>
			) : null}
			{remoteChanged || conflict ? (
				<Button
					size="sm"
					disabled={reloading}
					onClick={async () => {
						setReloading(true);
						try {
							const latest = await onReload();
							if (latest) {
								baseline.current = {
									policy: latest.policy ?? EMPTY_POLICY,
									etag: latest.etag,
								};
								setPolicy(latest.policy ?? EMPTY_POLICY);
								save.reset();
							}
						} finally {
							setReloading(false);
						}
					}}
				>
					Reload latest policy and discard edits
				</Button>
			) : null}
			<RefusalNote error={save.error} />
			<p className="text-sm text-ink-2">
				{changed} pending {changed === 1 ? "change" : "changes"}
			</p>
			<WhyDisabled reason={disabledReason} />
			<Button
				variant="primary"
				size="sm"
				disabled={disabled || changed === 0}
				onClick={() => save.mutate(policy)}
			>
				{save.isPending ? "Saving…" : "Save guardrail policy"}
			</Button>
			{save.isSuccess ? (
				<output className="text-sm text-ok-ink">Guardrail policy saved</output>
			) : null}
		</div>
	);
}

export function GuardrailPolicyEditor() {
	const q = useControlQuery<PolicyView>("guardrails/policy");
	const { allowed, reason } = useCan("edit_policies");
	if (q.isError && q.error.status === 403)
		return (
			<Panel title="Guardrail policy unavailable">
				<EmptyNote>
					Only workspace admins can view and change guardrail policy.
				</EmptyNote>
			</Panel>
		);
	if (q.isError && q.error.status === 404)
		return (
			<Panel title="Guardrail policy unavailable">
				<EmptyNote>
					This gateway does not serve the guardrail policy route.
				</EmptyNote>
			</Panel>
		);
	return (
		<Boundary query={q} resource="guardrail policy" rows={4}>
			{(view) =>
				view.policy === null ||
				(view.policy &&
					typeof view.policy === "object" &&
					view.policy.rails &&
					typeof view.policy.rails === "object" &&
					!Array.isArray(view.policy.rails)) ? (
					<GuardrailForm
						view={view}
						allowed={allowed}
						reason={reason}
						onReload={() => q.refetch().then((result) => result.data ?? null)}
					/>
				) : (
					<Panel title="Guardrail policy unavailable">
						<EmptyNote>
							The saved policy cannot be opened safely in this editor. Correct
							it through the API, then reload this page.
						</EmptyNote>
					</Panel>
				)
			}
		</Boundary>
	);
}
