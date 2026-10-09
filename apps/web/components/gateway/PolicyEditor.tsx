"use client";
/**
 * OG-60 — the ONE policy editor (`OG-20` rules, `OG-21` limits, `OG-22` budgets) used at
 * all three layers: the workspace (`PUT /v1/controls/policy`), a project and a key
 * (`PATCH …`). It edits the document the gateway validates strictly; the gateway's 400
 * names the dotted field and this puts the text beside it.
 */

import {
	BUDGET_WINDOWS,
	type BudgetForm,
	END_USER_WINDOWS,
	type FormError,
	type PolicyForm,
	type PolicyScope,
	formToPolicy,
	newBudgetForm,
	policyToForm,
} from "@/lib/gateway-controls";
import { Button } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import { type ControlError, RefusalNote } from "./control";
import { Field, WhyDisabled, inputClass, monoInput } from "./fields";

const SCOPE_NOUN: Record<PolicyScope, string> = {
	workspace: "every key in the workspace",
	project: "every key in this project",
	key: "this key",
};

function BudgetFields({
	label,
	value,
	onChange,
	windows,
	disabled,
	err,
	prefix,
	hint,
}: {
	label: string;
	value: BudgetForm | null;
	onChange: (b: BudgetForm | null) => void;
	windows: readonly string[];
	disabled: boolean;
	err: (f: string) => string | null;
	prefix: string;
	hint: string;
}) {
	if (!value) {
		return (
			<div className="space-y-1">
				<p className="text-sm text-ink-2">
					No {label.toLowerCase()}. {hint}
				</p>
				<Button
					size="sm"
					disabled={disabled}
					onClick={() => onChange(newBudgetForm())}
				>
					Add {label.toLowerCase()}
				</Button>
			</div>
		);
	}
	const set = (patch: Partial<BudgetForm>) => onChange({ ...value, ...patch });
	return (
		<div className="space-y-3">
			<div className="grid gap-3 sm:grid-cols-3">
				<Field label="Budget (USD)" error={err(`${prefix}.usd`)}>
					<input
						className={inputClass}
						inputMode="decimal"
						disabled={disabled}
						value={value.usd}
						onChange={(e) => set({ usd: e.target.value })}
					/>
				</Field>
				<Field label="Window (UTC)" error={err(`${prefix}.window`)}>
					<select
						className={inputClass}
						disabled={disabled}
						value={value.window}
						onChange={(e) => set({ window: e.target.value })}
					>
						{windows.map((w) => (
							<option key={w} value={w}>
								{w}
							</option>
						))}
					</select>
				</Field>
				<Field
					label="When spent"
					error={err(`${prefix}.mode`)}
					hint={
						value.mode === "hard"
							? "Hard: requests are refused (402) once the budget is spent."
							: "Soft: requests keep flowing; alerts fire at the thresholds."
					}
				>
					<select
						className={inputClass}
						disabled={disabled}
						value={value.mode}
						onChange={(e) =>
							set({ mode: e.target.value === "soft" ? "soft" : "hard" })
						}
					>
						<option value="hard">Hard — refuse</option>
						<option value="soft">Soft — allow and alert</option>
					</select>
				</Field>
			</div>
			<div className="grid gap-3 sm:grid-cols-2">
				<Field
					label="Alert at percent of budget"
					hint="Comma-separated, e.g. 50, 80, 100. Delivered to your spend-alert channels."
					error={err(`${prefix}.alert_at_percent`)}
				>
					<input
						className={monoInput}
						disabled={disabled}
						value={value.alertPercent}
						onChange={(e) => set({ alertPercent: e.target.value })}
					/>
				</Field>
				<Field
					label="Alert at spend (USD)"
					hint="Comma-separated amounts, e.g. 25, 100."
					error={err(`${prefix}.alert_at_usd`)}
				>
					<input
						className={monoInput}
						disabled={disabled}
						value={value.alertUsd}
						onChange={(e) => set({ alertUsd: e.target.value })}
					/>
				</Field>
			</div>
			<Button size="sm" disabled={disabled} onClick={() => onChange(null)}>
				Remove {label.toLowerCase()}
			</Button>
		</div>
	);
}

function Group({
	title,
	children,
}: { title: string; children: React.ReactNode }) {
	return (
		<fieldset className="space-y-3 border-t border-line pt-4 first:border-0 first:pt-0">
			<legend className="mb-2 text-sm font-semibold">{title}</legend>
			{children}
		</fieldset>
	);
}

export function PolicyEditor({
	scope,
	value,
	onChange,
	disabled,
	errors,
}: {
	scope: PolicyScope;
	value: PolicyForm;
	onChange: (f: PolicyForm) => void;
	disabled: boolean;
	/** Dotted field (without the `policy.` prefix) → message. */
	errors: Record<string, string>;
}) {
	const set = (patch: Partial<PolicyForm>) => onChange({ ...value, ...patch });
	const err = (f: string) => errors[f] ?? null;
	const text = (k: keyof PolicyForm) => String(value[k] ?? "");
	return (
		<div className="space-y-5">
			<Group title="Models and providers">
				<div className="grid gap-3 sm:grid-cols-2">
					<Field
						label="Allowed models"
						hint="One per line; * globs allowed (gpt-4o*). Empty = any model not denied."
						error={err("models")}
					>
						<textarea
							className={monoInput}
							rows={3}
							disabled={disabled}
							value={text("modelsAllow")}
							onChange={(e) => set({ modelsAllow: e.target.value })}
						/>
					</Field>
					<Field label="Denied models" hint="A deny always wins over an allow.">
						<textarea
							className={monoInput}
							rows={3}
							disabled={disabled}
							value={text("modelsDeny")}
							onChange={(e) => set({ modelsDeny: e.target.value })}
						/>
					</Field>
					<Field
						label="Allowed providers"
						hint="Provider ids, one per line. Empty = any provider not denied."
						error={err("providers")}
					>
						<textarea
							className={monoInput}
							rows={3}
							disabled={disabled}
							value={text("providersAllow")}
							onChange={(e) => set({ providersAllow: e.target.value })}
						/>
					</Field>
					<Field label="Denied providers">
						<textarea
							className={monoInput}
							rows={3}
							disabled={disabled}
							value={text("providersDeny")}
							onChange={(e) => set({ providersDeny: e.target.value })}
						/>
					</Field>
				</div>
				<Field
					label="Source IP ranges (CIDR)"
					hint="API keys may only be used from these ranges. One per line, e.g. 203.0.113.0/24. Empty = any address."
					error={err("source_ips")}
				>
					<textarea
						className={monoInput}
						rows={2}
						disabled={disabled}
						value={text("sourceIps")}
						onChange={(e) => set({ sourceIps: e.target.value })}
					/>
				</Field>
			</Group>

			{scope !== "workspace" ? (
				<Group title="Request size caps and required labels">
					<div className="grid gap-3 sm:grid-cols-3">
						<Field label="Max input tokens" error={err("max_input_tokens")}>
							<input
								className={inputClass}
								inputMode="numeric"
								disabled={disabled}
								value={text("maxInputTokens")}
								onChange={(e) => set({ maxInputTokens: e.target.value })}
							/>
						</Field>
						<Field label="Max output tokens" error={err("max_output_tokens")}>
							<input
								className={inputClass}
								inputMode="numeric"
								disabled={disabled}
								value={text("maxOutputTokens")}
								onChange={(e) => set({ maxOutputTokens: e.target.value })}
							/>
						</Field>
						<Field label="Max body bytes" error={err("max_body_bytes")}>
							<input
								className={inputClass}
								inputMode="numeric"
								disabled={disabled}
								value={text("maxBodyBytes")}
								onChange={(e) => set({ maxBodyBytes: e.target.value })}
							/>
						</Field>
					</div>
					<div className="grid gap-3 sm:grid-cols-2">
						<Field
							label="Required tags"
							hint="A request without every tag is refused. One per line."
							error={err("required_tags")}
						>
							<textarea
								className={monoInput}
								rows={2}
								disabled={disabled}
								value={text("requiredTags")}
								onChange={(e) => set({ requiredTags: e.target.value })}
							/>
						</Field>
						<Field
							label="Required metadata keys"
							error={err("required_metadata_keys")}
						>
							<textarea
								className={monoInput}
								rows={2}
								disabled={disabled}
								value={text("requiredMetadataKeys")}
								onChange={(e) => set({ requiredMetadataKeys: e.target.value })}
							/>
						</Field>
					</div>
				</Group>
			) : (
				<p className="text-xs text-ink-3">
					Token, body and label caps are set on a project or key, not the
					workspace. An emergency block is under Emergency controls.
				</p>
			)}

			<Group title="Rate limits (per minute)">
				<div className="grid items-start gap-3 sm:grid-cols-4">
					<Field label="Requests / min" error={err("limits.rpm")}>
						<input
							className={inputClass}
							inputMode="numeric"
							disabled={disabled}
							value={text("rpm")}
							onChange={(e) => set({ rpm: e.target.value })}
						/>
					</Field>
					<Field label="Tokens / min" error={err("limits.tpm")}>
						<input
							className={inputClass}
							inputMode="numeric"
							disabled={disabled}
							value={text("tpm")}
							onChange={(e) => set({ tpm: e.target.value })}
						/>
					</Field>
					<Field
						label="End user: req / min"
						error={err("limits.per_end_user.rpm")}
					>
						<input
							className={inputClass}
							inputMode="numeric"
							disabled={disabled}
							value={text("perEndUserRpm")}
							onChange={(e) => set({ perEndUserRpm: e.target.value })}
						/>
					</Field>
					<Field
						label="End user: tokens / min"
						error={err("limits.per_end_user.tpm")}
					>
						<input
							className={inputClass}
							inputMode="numeric"
							disabled={disabled}
							value={text("perEndUserTpm")}
							onChange={(e) => set({ perEndUserTpm: e.target.value })}
						/>
					</Field>
				</div>
				<div className="space-y-2">
					<p className="text-sm font-medium">Per-model limits</p>
					{value.perModel.length === 0 ? (
						<p className="text-sm text-ink-2">
							No per-model limits. Every model shares the limits above.
						</p>
					) : (
						value.perModel.map((m, i) => (
							<div
								// biome-ignore lint/suspicious/noArrayIndexKey: editable rows have no stable id
								key={i}
								className="grid gap-2 sm:grid-cols-[2fr_1fr_1fr_auto]"
							>
								<Field
									label={i === 0 ? "Model or pattern" : ""}
									error={err(`limits.per_model.${i}.model`)}
								>
									<input
										className={monoInput}
										aria-label={`Per-model limit ${i + 1} model`}
										disabled={disabled}
										value={m.model}
										onChange={(e) =>
											set({
												perModel: value.perModel.map((x, j) =>
													j === i ? { ...x, model: e.target.value } : x,
												),
											})
										}
									/>
								</Field>
								<Field
									label={i === 0 ? "Req / min" : ""}
									error={err(`limits.per_model.${i}.rpm`)}
								>
									<input
										className={inputClass}
										aria-label={`Per-model limit ${i + 1} requests per minute`}
										disabled={disabled}
										value={m.rpm}
										onChange={(e) =>
											set({
												perModel: value.perModel.map((x, j) =>
													j === i ? { ...x, rpm: e.target.value } : x,
												),
											})
										}
									/>
								</Field>
								<Field
									label={i === 0 ? "Tokens / min" : ""}
									error={err(`limits.per_model.${i}.tpm`)}
								>
									<input
										className={inputClass}
										aria-label={`Per-model limit ${i + 1} tokens per minute`}
										disabled={disabled}
										value={m.tpm}
										onChange={(e) =>
											set({
												perModel: value.perModel.map((x, j) =>
													j === i ? { ...x, tpm: e.target.value } : x,
												),
											})
										}
									/>
								</Field>
								<div className="flex items-end">
									<Button
										size="sm"
										disabled={disabled}
										aria-label={`Remove per-model limit ${i + 1}`}
										onClick={() =>
											set({
												perModel: value.perModel.filter((_, j) => j !== i),
											})
										}
									>
										Remove
									</Button>
								</div>
							</div>
						))
					)}
					<Button
						size="sm"
						disabled={disabled}
						onClick={() =>
							set({
								perModel: [...value.perModel, { model: "", rpm: "", tpm: "" }],
							})
						}
					>
						Add a per-model limit
					</Button>
				</div>
			</Group>

			<Group title="Budget">
				<BudgetFields
					label="Budget"
					value={value.budget}
					onChange={(budget) => set({ budget })}
					windows={BUDGET_WINDOWS}
					disabled={disabled}
					err={err}
					prefix="budget"
					hint={`Spend is summed over the window for ${SCOPE_NOUN[scope]}.`}
				/>
			</Group>
			<Group title="Per-end-user budget">
				<BudgetFields
					label="End-user budget"
					value={value.endUserBudget}
					onChange={(endUserBudget) => set({ endUserBudget })}
					windows={END_USER_WINDOWS}
					disabled={disabled}
					err={err}
					prefix="end_user_budget"
					hint="Each end user (the request's user id) gets this budget on its own."
				/>
			</Group>
		</div>
	);
}

/** Map the gateway's `policy.<dotted>` field (or a form error) to the editor's keys. */
export function fieldErrors(
	form: FormError[],
	gateway: ControlError | null | undefined,
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const e of form) out[e.field] = e.message;
	const f = gateway?.refusal.field;
	if (f) {
		const key = f.replace(/^policy\.?/, "");
		out[key === "" ? "models" : key] = gateway?.refusal.message ?? "";
	}
	return out;
}

/**
 * A stateful policy form around `PolicyEditor`: seeds from a stored document, converts on
 * save, shows form + gateway field errors and the refusal, and disables itself with the
 * reason when the role cannot write.
 */
export function PolicyCard({
	scope,
	doc,
	canEdit,
	reason,
	saving,
	error,
	onSave,
	saveLabel = "Save policy",
	resetKey,
}: {
	scope: PolicyScope;
	doc: unknown;
	canEdit: boolean;
	reason: string | null;
	saving: boolean;
	error: ControlError | null | undefined;
	/** `null` = clear the policy. */
	onSave: (doc: Record<string, unknown> | null) => void;
	saveLabel?: string;
	/** Changes when a new server document should replace the local draft. */
	resetKey?: string;
}) {
	const [form, setForm] = useState<PolicyForm>(() => policyToForm(doc));
	const [formErrors, setFormErrors] = useState<FormError[]>([]);
	// biome-ignore lint/correctness/useExhaustiveDependencies: reseed only when the server doc changes
	useEffect(() => {
		setForm(policyToForm(doc));
		setFormErrors([]);
	}, [resetKey ?? JSON.stringify(doc ?? null)]);
	return (
		<div className="space-y-4">
			<PolicyEditor
				scope={scope}
				value={form}
				onChange={setForm}
				disabled={!canEdit || saving}
				errors={fieldErrors(formErrors, error)}
			/>
			<RefusalNote error={error} />
			<div className="flex flex-wrap items-center gap-3">
				<Button
					variant="primary"
					size="sm"
					disabled={!canEdit || saving}
					onClick={() => {
						const { doc: next, errors } = formToPolicy(form, scope);
						setFormErrors(errors);
						if (errors.length === 0) onSave(next);
					}}
				>
					{saving ? "Saving…" : saveLabel}
				</Button>
				{formErrors.length > 0 ? (
					<span role="alert" className="text-sm text-danger-ink">
						Fix the highlighted fields first.
					</span>
				) : null}
			</div>
			<WhyDisabled reason={reason} />
		</div>
	);
}
