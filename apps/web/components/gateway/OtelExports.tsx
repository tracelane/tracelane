"use client";
/**
 * Gateway › OTel export — `OG-50`: OTLP/HTTP span exports. `GET /v1/exports/otel` lists
 * them (header NAMES only, the URL as host + path); create, enable/disable, delete and a
 * synthetic-span test ride the same route. Delivery is best-effort and in-memory: the
 * counters are since gateway start, and the page says so.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import {
	Badge,
	Button,
	ConfirmDialog,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
import { useState } from "react";
import {
	Boundary,
	RefusalNote,
	controlRequest,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

export interface OtelExport {
	id: string;
	name: string;
	url: string;
	header_names: string[];
	enabled: boolean;
	include_content: boolean;
	sample_ratio: number;
	only_errors: boolean;
	status: string;
	last_success_at: string | null;
	last_error_class: string | null;
	delivered: number;
	dropped: number;
	failed: number;
}

interface OtelList {
	exports: OtelExport[];
	plan: { export_enabled: boolean; max_exports: number | null };
}

/** `Name: value` lines to the headers map the route takes. A line without `:` is refused. */
export function parseHeaderLines(
	text: string,
): { headers: Record<string, string> } | { error: string } {
	const headers: Record<string, string> = {};
	for (const raw of text.split("\n")) {
		const line = raw.trim();
		if (!line) continue;
		const i = line.indexOf(":");
		if (i <= 0) return { error: `“${line.slice(0, 40)}” is not Name: value.` };
		headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
	}
	return { headers };
}

function CreateExport({ allowed }: { allowed: boolean }) {
	const [name, setName] = useState("");
	const [url, setUrl] = useState("");
	const [headersText, setHeadersText] = useState("");
	const [content, setContent] = useState(false);
	const [errorsOnly, setErrorsOnly] = useState(false);
	const [ratio, setRatio] = useState("1");
	const create = useControlWrite<OtelExport, Record<string, unknown>>(
		"POST",
		"exports/otel",
		["exports/otel"],
	);
	const parsed = parseHeaderLines(headersText);
	const ratioN = Number(ratio);
	const ratioBad = !(ratioN >= 0 && ratioN <= 1) || ratio.trim() === "";
	const fieldError = (f: string) =>
		create.error?.refusal.field === f ? create.error.refusal.message : null;
	return (
		<div className="space-y-3">
			<div className="grid gap-3 sm:grid-cols-2">
				<Field label="Name" error={fieldError("name")}>
					<input
						className={inputClass}
						disabled={!allowed || create.isPending}
						value={name}
						maxLength={128}
						onChange={(e) => setName(e.target.value)}
					/>
				</Field>
				<Field
					label="OTLP/HTTP traces URL"
					hint="https only, e.g. https://collector.example.com/v1/traces. Shown afterwards as host + path."
					error={fieldError("url")}
				>
					<input
						className={inputClass}
						disabled={!allowed || create.isPending}
						value={url}
						onChange={(e) => setUrl(e.target.value)}
					/>
				</Field>
				<Field
					label="Headers"
					hint="One Name: value per line. Values are stored encrypted and never shown again — only the names are."
					error={"error" in parsed ? parsed.error : fieldError("headers")}
				>
					<textarea
						className={`${inputClass} font-mono`}
						rows={3}
						disabled={!allowed || create.isPending}
						value={headersText}
						onChange={(e) => setHeadersText(e.target.value)}
					/>
				</Field>
				<div className="space-y-2">
					<Field
						label="Sample ratio (0–1)"
						error={
							ratioBad ? "A number from 0 to 1." : fieldError("sample_ratio")
						}
					>
						<input
							className={inputClass}
							inputMode="decimal"
							disabled={!allowed || create.isPending}
							value={ratio}
							onChange={(e) => setRatio(e.target.value)}
						/>
					</Field>
					<span className="flex items-center gap-2 text-sm">
						<input
							type="checkbox"
							disabled={!allowed || create.isPending}
							checked={content}
							onChange={(e) => setContent(e.target.checked)}
						/>
						Include prompt and response text (only when the workspace records
						it)
					</span>
					<span className="flex items-center gap-2 text-sm">
						<input
							type="checkbox"
							disabled={!allowed || create.isPending}
							checked={errorsOnly}
							onChange={(e) => setErrorsOnly(e.target.checked)}
						/>
						Errors only
					</span>
				</div>
			</div>
			<RefusalNote error={create.error} fieldOnly />
			<Button
				variant="primary"
				size="sm"
				disabled={
					!allowed ||
					create.isPending ||
					!name.trim() ||
					!url.trim() ||
					"error" in parsed ||
					ratioBad
				}
				onClick={() =>
					create.mutate(
						{
							name: name.trim(),
							url: url.trim(),
							...("headers" in parsed && Object.keys(parsed.headers).length > 0
								? { headers: parsed.headers }
								: {}),
							include_content: content,
							only_errors: errorsOnly,
							sample_ratio: ratioN,
						},
						{
							onSuccess: () => {
								setName("");
								setUrl("");
								setHeadersText("");
							},
						},
					)
				}
			>
				{create.isPending ? "Adding…" : "Add export"}
			</Button>
		</div>
	);
}

function ExportRow({ e, allowed }: { e: OtelExport; allowed: boolean }) {
	const [confirm, setConfirm] = useState(false);
	const [test, setTest] = useState<
		| { state: "idle" }
		| { state: "busy" }
		| { state: "done"; ok: boolean; cls: string; ms: number }
		| { state: "fail"; message: string }
	>({ state: "idle" });
	const toggle = useControlWrite<OtelExport, { enabled: boolean }>(
		"PATCH",
		`exports/otel/${e.id}`,
		["exports/otel"],
	);
	const del = useControlWrite<void, void>("DELETE", `exports/otel/${e.id}`, [
		"exports/otel",
	]);
	return (
		<TR>
			<TD>{e.name}</TD>
			<TD mono className="break-all">
				{e.url}
				{e.header_names.length > 0 ? (
					<span className="block text-xs text-ink-3">
						headers: {e.header_names.join(", ")}
					</span>
				) : null}
			</TD>
			<TD>
				<Badge tone={e.enabled ? "ok" : "neutral"}>
					{e.enabled ? e.status : "disabled"}
				</Badge>
				{e.last_error_class ? (
					<span className="block text-xs text-danger-ink">
						{e.last_error_class}
					</span>
				) : null}
				<span className="block text-xs text-ink-3">
					{e.last_success_at
						? `last delivered ${formatDateTimeUtc(e.last_success_at)}`
						: "never delivered"}
				</span>
			</TD>
			<TD numeric>
				{e.delivered} / {e.dropped} / {e.failed}
			</TD>
			<TD>
				<div className="flex flex-wrap items-center gap-2">
					<Button
						size="sm"
						disabled={!allowed || toggle.isPending}
						aria-label={`${e.enabled ? "Disable" : "Enable"} ${e.name}`}
						onClick={() => toggle.mutate({ enabled: !e.enabled })}
					>
						{e.enabled ? "Disable" : "Enable"}
					</Button>
					<Button
						size="sm"
						disabled={!allowed || test.state === "busy"}
						aria-label={`Send a test span to ${e.name}`}
						onClick={async () => {
							setTest({ state: "busy" });
							try {
								const r = await controlRequest<{
									ok: boolean;
									class: string;
									latency_ms: number;
								}>("POST", `exports/otel/${e.id}/test`, {});
								setTest({
									state: "done",
									ok: r.ok,
									cls: r.class,
									ms: r.latency_ms,
								});
							} catch (err) {
								setTest({
									state: "fail",
									message:
										err instanceof Error ? err.message : "The test failed.",
								});
							}
						}}
					>
						{test.state === "busy" ? "Sending…" : "Send test"}
					</Button>
					<Button
						size="sm"
						disabled={!allowed}
						aria-label={`Delete ${e.name}`}
						onClick={() => setConfirm(true)}
					>
						Delete
					</Button>
					{test.state === "done" ? (
						<output
							className={`text-xs ${test.ok ? "text-ok-ink" : "text-danger-ink"}`}
						>
							{test.ok ? "Accepted" : "Refused"} ({test.cls}, {test.ms} ms)
						</output>
					) : null}
					{test.state === "fail" ? (
						<span role="alert" className="text-xs text-danger-ink">
							{test.message}
						</span>
					) : null}
					<RefusalNote error={toggle.error} />
				</div>
				<ConfirmDialog
					open={confirm}
					onClose={() => setConfirm(false)}
					title={`Delete ${e.name}?`}
					confirmLabel="Delete export"
					busy={del.isPending}
					error={del.error?.refusal.message ?? null}
					onConfirm={() =>
						del.mutate(undefined, { onSuccess: () => setConfirm(false) })
					}
				>
					<p className="text-sm text-ink-2">
						Spans stop being sent to this collector. Nothing already delivered
						is recalled, and Tracelane’s own trace storage is unaffected.
					</p>
				</ConfirmDialog>
			</TD>
		</TR>
	);
}

export function OtelExports() {
	const q = useControlQuery<OtelList>("exports/otel");
	const { allowed, reason } = useCan("edit_policies");
	return (
		<Boundary query={q} resource="OTel exports" rows={2}>
			{({ exports: rows, plan }) => (
				<div className="space-y-6">
					<Panel
						id="otel-exports"
						title="OTel export"
						description="Send this workspace’s spans to your own OTLP/HTTP collector. Delivery is best-effort: in memory, retried a bounded number of times, and counters restart with the gateway."
					>
						{!plan.export_enabled ? (
							<EmptyNote>
								Span export is not part of this workspace’s plan, so adding or
								enabling an export is refused.
							</EmptyNote>
						) : null}
						{rows.length === 0 ? (
							<EmptyNote>
								No exports: spans go to Tracelane’s own storage only.
							</EmptyNote>
						) : (
							<div className="overflow-x-auto">
								<Table className="w-full text-left text-sm">
									<THead>
										<TR>
											<TH>Name</TH>
											<TH>Endpoint</TH>
											<TH>Status</TH>
											<TH numeric>Delivered / dropped / failed</TH>
											<TH>Actions</TH>
										</TR>
									</THead>
									<TBody>
										{rows.map((e) => (
											<ExportRow key={e.id} e={e} allowed={allowed} />
										))}
									</TBody>
								</Table>
							</div>
						)}
						<WhyDisabled reason={reason} />
					</Panel>
					<Panel
						id="otel-create"
						title="Add an export"
						description={
							plan.max_exports !== null
								? `Your plan allows up to ${plan.max_exports}.`
								: undefined
						}
					>
						<CreateExport allowed={allowed} />
					</Panel>
				</div>
			)}
		</Boundary>
	);
}
