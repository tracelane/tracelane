"use client";
import { apiFetchRaw } from "@/lib/api-fetch";
import {
	type ActivePolicy,
	TEMPLATES,
	type TemplateId,
	type TemplateParams,
	buildPolicyDocument,
	describeLimit,
	findExisting,
	summarizeTemplate,
	validateTemplateParams,
} from "@/lib/policy-templates";
import { Button, ConfirmDialog } from "@tracelanedev/ui";
import { useState } from "react";

const PREVIEW_ID = "00000000-0000-4000-8000-000000000000";
const field =
	"w-full rounded border border-line bg-surface px-3 py-2 text-sm min-h-11";

/** Start-from-a-template form: parameters, a live preview of the exact document, then publish. */
export function PolicyTemplates({
	servers,
	policies,
	canEdit,
}: {
	servers: { id: string; name: string }[];
	policies: ActivePolicy[];
	canEdit: boolean;
}) {
	const [template, setTemplate] = useState<TemplateId>("payments");
	const info = TEMPLATES.find((t) => t.id === template) ?? TEMPLATES[0];
	const [server, setServer] = useState(servers[0]?.id ?? "");
	const [tool, setTool] = useState<Record<string, string>>({});
	const [limit, setLimit] = useState("");
	const [approved, setApproved] = useState("");
	const [minutes, setMinutes] = useState("60");
	const [unit, setUnit] = useState("");
	const [args, setArgs] = useState<Record<string, string>>({});
	const [confirm, setConfirm] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [done, setDone] = useState("");

	if (!info) return null;
	const toolName = tool[template] ?? info.defaultTool;
	const argNames = { ...info.defaultArgs, ...args };
	const params: TemplateParams = {
		amountUnit:
			unit === "cents"
				? "cents"
				: unit === "whole_dollars"
					? "whole_dollars"
					: undefined,
		toolName,
		limit: Number(limit),
		approved: approved
			.split("\n")
			.map((s) => s.trim())
			.filter(Boolean),
		approvalMinutes: Number(minutes),
		args: argNames,
	};
	const errors = limit === "" ? {} : validateTemplateParams(template, params);
	const existing = findExisting(policies, server, toolName);
	const preview = buildPolicyDocument(template, params, {
		serverId: server || PREVIEW_ID,
		toolRef: existing?.toolRef ?? PREVIEW_ID,
		policyId: PREVIEW_ID,
		existing,
	});
	const ready = canEdit && preview.ok && limit !== "";

	async function publish() {
		setBusy(true);
		setError("");
		try {
			const res = await apiFetchRaw("/api/settings/action-policies", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ template, server_id: server, params }),
			});
			const body = await res.json().catch(() => ({}));
			if (!res.ok) {
				setError(
					body.reason ??
						"Not published. The service did not answer. Try again.",
				);
				return;
			}
			setDone(`Published for ${toolName}. Reload to see it in the list.`);
			setConfirm(false);
		} catch {
			setError("Not published. The service did not answer. Try again.");
		} finally {
			setBusy(false);
		}
	}

	return (
		<section
			className="space-y-3 rounded-card border border-line bg-surface p-4 sm:p-5"
			aria-labelledby="templates-title"
		>
			<h3 id="templates-title" className="text-sm font-semibold">
				Start from a template
			</h3>
			<div className="flex flex-wrap gap-2">
				{TEMPLATES.map((t) => (
					<Button
						key={t.id}
						onClick={() => {
							setTemplate(t.id);
							setDone("");
							setError("");
						}}
						aria-pressed={t.id === template}
					>
						{t.title}
					</Button>
				))}
			</div>
			<p className="text-sm text-ink-2">{info.summary}</p>
			{servers.length === 0 ? (
				<p className="text-sm">
					Register a tool server first; policies attach to its tools.
				</p>
			) : (
				<div className="grid gap-3 sm:grid-cols-2">
					<label className="space-y-1 text-sm">
						Tool server
						<select
							className={field}
							value={server}
							onChange={(e) => setServer(e.target.value)}
						>
							{servers.map((s) => (
								<option key={s.id} value={s.id}>
									{s.name}
								</option>
							))}
						</select>
					</label>
					<label className="space-y-1 text-sm">
						Tool name
						<input
							className={field}
							value={toolName}
							onChange={(e) => setTool({ ...tool, [template]: e.target.value })}
						/>
						{errors.toolName && <Err>{errors.toolName}</Err>}
					</label>
					<label className="space-y-1 text-sm">
						{info.limitLabel}
						<input
							className={field}
							inputMode="numeric"
							value={limit}
							onChange={(e) => setLimit(e.target.value)}
						/>
						{errors.limit && <Err>{errors.limit}</Err>}
					</label>
					<label className="space-y-1 text-sm">
						Approval window (minutes)
						<input
							className={field}
							inputMode="numeric"
							value={minutes}
							onChange={(e) => setMinutes(e.target.value)}
						/>
						{errors.approvalMinutes && <Err>{errors.approvalMinutes}</Err>}
					</label>
					{template === "payments" && (
						<label className="space-y-1 text-sm sm:col-span-2">
							The tool's amount is in
							<select
								className={field}
								value={unit}
								onChange={(e) => setUnit(e.target.value)}
							>
								<option value="">Choose…</option>
								<option value="cents">Cents (1500 means 15 dollars)</option>
								<option value="whole_dollars">
									Whole dollars (15 means 15 dollars)
								</option>
							</select>
							{errors.amountUnit && <Err>{errors.amountUnit}</Err>}
						</label>
					)}
					<label className="space-y-1 text-sm sm:col-span-2">
						{info.approvedLabel} (one per line)
						<textarea
							className={field}
							rows={4}
							value={approved}
							onChange={(e) => setApproved(e.target.value)}
						/>
						{errors.approved && <Err>{errors.approved}</Err>}
					</label>
					<details className="text-sm sm:col-span-2">
						<summary className="cursor-pointer">Argument names</summary>
						<div className="mt-2 grid gap-3 sm:grid-cols-3">
							{Object.keys(info.defaultArgs).map((k) => (
								<label key={k} className="space-y-1">
									{k.replace("_", " ")}
									<input
										className={field}
										value={argNames[k] ?? ""}
										onChange={(e) => setArgs({ ...args, [k]: e.target.value })}
									/>
									{errors[`args.${k}`] && <Err>{errors[`args.${k}`]}</Err>}
								</label>
							))}
						</div>
						{errors.args && <Err>{errors.args}</Err>}
					</details>
				</div>
			)}
			{preview.ok && limit !== "" && (
				<p className="text-sm" aria-live="polite">
					{summarizeTemplate(template, params)}
				</p>
			)}
			{!canEdit && (
				<p className="text-sm text-ink-2">
					Only workspace owners and admins can publish policies.
				</p>
			)}
			{done && (
				<p className="text-sm" aria-live="polite">
					{done}
				</p>
			)}
			{error && !confirm && (
				<p role="alert" className="text-danger-ink">
					{error}
				</p>
			)}
			<Button disabled={!ready || busy} onClick={() => setConfirm(true)}>
				Publish policy
			</Button>
			<ConfirmDialog
				open={confirm}
				title={`Publish policy for ${toolName}?`}
				confirmLabel="Publish"
				onClose={() => setConfirm(false)}
				onConfirm={() => void publish()}
				busy={busy}
				error={error}
			>
				<p>
					{describeLimit(template, params)}{" "}
					{existing
						? `This replaces version ${existing.policyVersion} of the policy for this tool. `
						: "This protects the tool. "}
					The activation is recorded in the change log.
				</p>
			</ConfirmDialog>
		</section>
	);
}

function Err({ children }: { children: React.ReactNode }) {
	return (
		<span role="alert" className="block text-danger-ink text-xs">
			{children}
		</span>
	);
}
