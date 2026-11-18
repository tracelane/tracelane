"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@tracelanedev/ui";
import { useEffect, useMemo, useRef, useState } from "react";
import {
	Boundary,
	type ControlError,
	RefusalNote,
	controlRequest,
	useCan,
	useControlQuery,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

type Strategy = "priority" | "weighted" | "latency" | "cost";
type Target = { model: string; weight?: number };
type VirtualModel = { strategy: Strategy; targets: Target[] };
type Pool = {
	provider: string;
	strategy: "priority" | "weighted";
	keys: { label: string; weight?: number }[];
};
type Rule = {
	id: string;
	wires: string[];
	match: {
		model: string;
		header?: { name: string; equals?: string; prefix?: string; in?: string[] };
		metadata?: { key: string; equals?: string; in?: string[] };
		[key: string]: unknown;
	};
	action: {
		route_to?: string;
		split?: {
			sticky_by: string[];
			on_missing_identity: "stable" | "random" | "refuse";
			arms: { name: string; route_to: string; bp?: number }[];
		};
	};
	salt?: string;
};
type RoutingDoc = {
	virtual_models?: Record<string, VirtualModel>;
	key_pools?: Pool[];
	rules?: Rule[];
	breaker?: { consecutive_failures: number; cooldown_secs: number };
	[key: string]: unknown;
};
interface RoutingView {
	doc: RoutingDoc;
	version: number;
	valid: boolean;
	can_edit: boolean;
	limits: {
		max_virtual_models: number;
		max_targets_per_model: number;
		max_pool_keys_per_provider: number;
		doc_max_bytes: number;
		rules: {
			max_rules: number;
			max_arms: number;
			max_match_value_bytes: number;
			sticky_key_max_bytes: number;
			match_header_denylist: string[];
		};
		breaker: {
			consecutive_failures_min: number;
			consecutive_failures_max: number;
			cooldown_secs_min: number;
			cooldown_secs_max: number;
		};
	};
}

function containsHidden(value: unknown): boolean {
	if (value === "[hidden]") return true;
	if (Array.isArray(value)) return value.some(containsHidden);
	return (
		value !== null &&
		typeof value === "object" &&
		Object.values(value).some(containsHidden)
	);
}

function changes(before: unknown, after: unknown): number {
	if (JSON.stringify(before) === JSON.stringify(after)) return 0;
	if (
		before === null ||
		after === null ||
		typeof before !== "object" ||
		typeof after !== "object" ||
		Array.isArray(before) !== Array.isArray(after)
	)
		return 1;
	const a = before as Record<string, unknown>;
	const b = after as Record<string, unknown>;
	return new Set([...Object.keys(a), ...Object.keys(b)]).size === 0
		? 1
		: [...new Set([...Object.keys(a), ...Object.keys(b)])].reduce(
				(n, key) => n + changes(a[key], b[key]),
				0,
			);
}

function validNumber(value: number, min: number, max: number) {
	return Number.isInteger(value) && value >= min && value <= max;
}

function validate(
	doc: RoutingDoc,
	limits: RoutingView["limits"],
): string | null {
	if (containsHidden(doc))
		return "This document contains a hidden value and cannot be edited safely here.";
	const models = Object.entries(doc.virtual_models ?? {});
	if (models.length > limits.max_virtual_models)
		return `At most ${limits.max_virtual_models} virtual models.`;
	for (const [name, model] of models) {
		if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/.test(name))
			return "A virtual model name must start with a letter or number and be at most 64 characters.";
		if (
			!model.targets.length ||
			model.targets.length > limits.max_targets_per_model
		)
			return `Each virtual model needs 1 to ${limits.max_targets_per_model} targets.`;
		if (
			new Set(model.targets.map((t) => t.model)).size !== model.targets.length
		)
			return "A model cannot appear twice in one target list.";
		for (const target of model.targets) {
			if (!target.model.trim()) return "Each target needs a model name.";
			if (target.weight !== undefined && !validNumber(target.weight, 1, 1000))
				return "A target weight must be from 1 to 1000.";
		}
	}
	for (const pool of doc.key_pools ?? []) {
		if (
			!pool.provider.trim() ||
			!pool.keys.length ||
			pool.keys.length > limits.max_pool_keys_per_provider
		)
			return `Each key pool needs a provider and 1 to ${limits.max_pool_keys_per_provider} keys.`;
		if (
			pool.keys.some(
				(k) =>
					!k.label.trim() ||
					(k.weight !== undefined && !validNumber(k.weight, 1, 1000)),
			)
		)
			return "Each pool key needs a label and a valid weight.";
	}
	if (
		new Set((doc.key_pools ?? []).map((p) => p.provider)).size !==
		(doc.key_pools ?? []).length
	)
		return "A provider can have only one key pool.";
	if ((doc.rules ?? []).length > limits.rules.max_rules)
		return `At most ${limits.rules.max_rules} rules.`;
	if (
		new Set((doc.rules ?? []).map((r) => r.id)).size !==
		(doc.rules ?? []).length
	)
		return "Rule names must be unique.";
	for (const rule of doc.rules ?? []) {
		if (!rule.id.trim() || !rule.match.model.trim())
			return "Each rule needs a name and a model to match.";
		const h = rule.match.header;
		if (
			h &&
			(!h.name.trim() ||
				!/^[a-z0-9!#$%&'*+.^_`|~-]+$/i.test(h.name) ||
				[h.equals, h.prefix, h.in].filter((v) => v !== undefined).length !==
					1 ||
				(h.equals !== undefined && !h.equals.trim()) ||
				(h.prefix !== undefined && !h.prefix.trim()) ||
				(h.in !== undefined &&
					(h.in.length === 0 || h.in.some((v) => !v.trim()))) ||
				[h.name, h.equals, h.prefix, ...(h.in ?? [])].some(
					(v) =>
						v !== undefined &&
						new TextEncoder().encode(v).length >
							limits.rules.max_match_value_bytes,
				) ||
				limits.rules.match_header_denylist.some(
					(d) => d.toLowerCase() === h.name.toLowerCase(),
				))
		)
			return "That header is denied, or its match value is empty.";
		const m = rule.match.metadata;
		if (
			m &&
			(!m.key.trim() ||
				[m.equals, m.in].filter((v) => v !== undefined).length !== 1 ||
				(m.equals !== undefined && !m.equals.trim()) ||
				(m.in !== undefined &&
					(m.in.length === 0 || m.in.some((v) => !v.trim()))))
		)
			return "Metadata matching needs a key and value.";
		if (rule.action.split) {
			const split = rule.action.split;
			if (
				split.arms.length < 2 ||
				split.arms.length > limits.rules.max_arms ||
				split.arms.some((a) => !a.name.trim() || !a.route_to.trim())
			)
				return `A split needs 2 to ${limits.rules.max_arms} named arms with targets.`;
			if (
				split.arms
					.slice(0, -1)
					.some((a) => a.bp === undefined || !validNumber(a.bp, 0, 10000)) ||
				split.arms.slice(0, -1).reduce((n, a) => n + (a.bp ?? 0), 0) > 10000
			)
				return "Split percentages must total at most 100%.";
			if (
				split.sticky_by.some(
					(s) =>
						s.startsWith("header:") &&
						(!s.slice(7).trim() ||
							s.length > limits.rules.sticky_key_max_bytes ||
							limits.rules.match_header_denylist.some(
								(d) => d.toLowerCase() === s.slice(7).toLowerCase(),
							)),
				)
			)
				return "That sticky header is denied.";
		} else if (!rule.action.route_to?.trim())
			return "A rule needs a route target.";
	}
	if (
		doc.breaker &&
		(!validNumber(
			doc.breaker.consecutive_failures,
			limits.breaker.consecutive_failures_min,
			limits.breaker.consecutive_failures_max,
		) ||
			!validNumber(
				doc.breaker.cooldown_secs,
				limits.breaker.cooldown_secs_min,
				limits.breaker.cooldown_secs_max,
			))
	)
		return "The breaker values must be within the shown limits.";
	if (
		new TextEncoder().encode(JSON.stringify(doc)).length > limits.doc_max_bytes
	)
		return `Routing document exceeds ${limits.doc_max_bytes} bytes.`;
	return null;
}

function RoutingForm({
	view,
	roleAllowed,
	roleReason,
	onReload,
}: {
	view: RoutingView;
	roleAllowed: boolean;
	roleReason: string | null;
	onReload: () => Promise<RoutingView | null>;
}) {
	const [doc, setDoc] = useState<RoutingDoc>(view.doc);
	const [reloading, setReloading] = useState(false);
	const baseline = useRef({ doc: view.doc, version: view.version });
	useEffect(() => {
		if (changes(doc, baseline.current.doc) === 0) {
			baseline.current = { doc: view.doc, version: view.version };
			setDoc(view.doc);
		}
	}, [doc, view.doc, view.version]);
	const qc = useQueryClient();
	const write = useMutation<
		{ doc: RoutingDoc; version: number },
		ControlError,
		RoutingDoc
	>({
		mutationFn: (next) =>
			controlRequest(
				"PUT",
				"routing",
				{ doc: next },
				{ "if-match": String(baseline.current.version) },
			),
		onSuccess: async (saved) => {
			baseline.current = { doc: saved.doc, version: saved.version };
			setDoc(saved.doc);
			await qc.invalidateQueries({ queryKey: ["gateway-control", "routing"] });
		},
	});
	const allowed = roleAllowed && view.can_edit;
	const conflict = write.error?.status === 409;
	const remoteChanged = view.version !== baseline.current.version;
	const disabled =
		!allowed || write.isPending || conflict || reloading || remoteChanged;
	const reason = !view.can_edit
		? "Your role cannot change routing."
		: roleReason;
	const count = useMemo(() => changes(baseline.current.doc, doc), [doc]);
	const invalid = validate(doc, view.limits);
	const models = Object.entries(doc.virtual_models ?? {});
	const patchModel = (name: string, model: VirtualModel) =>
		setDoc((d) => ({
			...d,
			virtual_models: { ...d.virtual_models, [name]: model },
		}));
	const patchRule = (i: number, rule: Rule) =>
		setDoc((d) => ({
			...d,
			rules: (d.rules ?? []).map((r, j) => (j === i ? rule : r)),
		}));
	const fieldError = (field: string) =>
		write.error?.refusal.field === field ? write.error.refusal.message : null;
	return (
		<div className="space-y-5">
			{!view.valid ? (
				<EmptyNote>
					The stored routing document needs correction before it can be used.
				</EmptyNote>
			) : null}
			<Panel
				title="Virtual models"
				description="A name your requests use, with concrete models tried in order."
			>
				{models.length === 0 ? (
					<EmptyNote>
						No virtual models yet. Add one to route a name to a concrete model.
					</EmptyNote>
				) : null}
				{models.map(([name, model]) => (
					<section
						key={name}
						className="space-y-3 border-t border-line pt-3"
						aria-label={`Virtual model ${name}`}
					>
						<div className="grid gap-3 sm:grid-cols-2">
							<Field
								label={`Virtual model ${name} name`}
								error={fieldError(`virtual_models.${name}`)}
							>
								<input
									className={inputClass}
									disabled={disabled}
									defaultValue={name}
									onBlur={(e) => {
										if (
											e.target.value !== name &&
											doc.virtual_models?.[e.target.value]
										) {
											e.target.value = name;
											return;
										}
										setDoc((d) => {
											const virtual_models = { ...d.virtual_models };
											delete virtual_models[name];
											virtual_models[e.target.value] = model;
											return { ...d, virtual_models };
										});
									}}
								/>
							</Field>
							<Field label={`Strategy for ${name}`}>
								<select
									className={inputClass}
									disabled={disabled}
									value={model.strategy}
									onChange={(e) =>
										patchModel(name, {
											...model,
											strategy: e.target.value as Strategy,
										})
									}
								>
									<option value="priority">Priority</option>
									<option value="weighted">Weighted</option>
									<option value="latency">Latency</option>
									<option value="cost">Cost</option>
								</select>
							</Field>
						</div>
						<p className="text-xs text-ink-3">
							Priority is the order below. The gateway identifies each target's
							provider from its model name.
						</p>
						{model.targets.map((target, i) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: These controlled rows have no local state; model names change as the user types.
							<div key={i} className="grid gap-2 sm:grid-cols-[1fr_7rem_auto]">
								<Field
									label={`Target ${i + 1} model`}
									error={fieldError(`virtual_models.${name}.targets[${i}]`)}
								>
									<input
										className={inputClass}
										disabled={disabled}
										value={target.model}
										onChange={(e) =>
											patchModel(name, {
												...model,
												targets: model.targets.map((t, j) =>
													j === i ? { ...t, model: e.target.value } : t,
												),
											})
										}
									/>
								</Field>
								<Field
									label={`Target ${i + 1} weight`}
									error={fieldError(
										`virtual_models.${name}.targets[${i}].weight`,
									)}
								>
									<input
										className={inputClass}
										type="number"
										min={1}
										max={1000}
										disabled={disabled}
										value={target.weight ?? ""}
										onChange={(e) =>
											patchModel(name, {
												...model,
												targets: model.targets.map((t, j) =>
													j === i
														? {
																...t,
																weight:
																	e.target.value === ""
																		? undefined
																		: Number(e.target.value),
															}
														: t,
												),
											})
										}
									/>
								</Field>
								<div className="flex flex-wrap items-end gap-1">
									<Button
										size="sm"
										aria-label={`Move target ${i + 1} up`}
										disabled={disabled || i === 0}
										onClick={() => {
											const targets = [...model.targets];
											if (i > 0) {
												const earlier = targets[i - 1];
												const current = targets[i];
												if (earlier && current) {
													targets[i - 1] = current;
													targets[i] = earlier;
												}
											}
											patchModel(name, { ...model, targets });
										}}
									>
										↑
									</Button>
									<Button
										size="sm"
										aria-label={`Remove target ${i + 1}`}
										disabled={disabled || model.targets.length <= 1}
										onClick={() =>
											patchModel(name, {
												...model,
												targets: model.targets.filter((_, j) => j !== i),
											})
										}
									>
										Remove
									</Button>
								</div>
							</div>
						))}
						<Button
							size="sm"
							disabled={
								disabled ||
								model.targets.length >= view.limits.max_targets_per_model
							}
							onClick={() =>
								patchModel(name, {
									...model,
									targets: [...model.targets, { model: "" }],
								})
							}
						>
							Add target to {name}
						</Button>
						<Button
							size="sm"
							disabled={disabled}
							onClick={() =>
								setDoc((d) => {
									const virtual_models = { ...d.virtual_models };
									delete virtual_models[name];
									return { ...d, virtual_models };
								})
							}
						>
							Remove virtual model {name}
						</Button>
					</section>
				))}
				<Button
					size="sm"
					disabled={disabled || models.length >= view.limits.max_virtual_models}
					onClick={() =>
						setDoc((d) => {
							let n = 1;
							while (d.virtual_models?.[`new-model-${n}`]) n++;
							return {
								...d,
								virtual_models: {
									...d.virtual_models,
									[`new-model-${n}`]: {
										strategy: "priority",
										targets: [{ model: "" }],
									},
								},
							};
						})
					}
				>
					Add virtual model
				</Button>
				<p className="text-xs text-ink-3">
					Up to {view.limits.max_virtual_models} virtual models and{" "}
					{view.limits.max_targets_per_model} targets per model.
				</p>
			</Panel>
			<Panel
				title="Provider key pools"
				description="Use stored key labels for a provider. Key order is the fallback order."
			>
				{(doc.key_pools ?? []).map((pool, i) => (
					// biome-ignore lint/suspicious/noArrayIndexKey: Controlled provider names change as the user types.
					<section key={i} className="space-y-2 border-t border-line pt-3">
						<div className="grid gap-2 sm:grid-cols-2">
							<Field
								label={`Pool ${i + 1} provider`}
								error={fieldError(`key_pools[${i}].provider`)}
							>
								<input
									className={inputClass}
									disabled={disabled}
									value={pool.provider}
									onChange={(e) =>
										setDoc((d) => ({
											...d,
											key_pools: (d.key_pools ?? []).map((p, j) =>
												j === i ? { ...p, provider: e.target.value } : p,
											),
										}))
									}
								/>
							</Field>
							<Field label={`Pool ${i + 1} strategy`}>
								<select
									className={inputClass}
									disabled={disabled}
									value={pool.strategy}
									onChange={(e) =>
										setDoc((d) => ({
											...d,
											key_pools: (d.key_pools ?? []).map((p, j) =>
												j === i
													? {
															...p,
															strategy: e.target.value as Pool["strategy"],
														}
													: p,
											),
										}))
									}
								>
									<option value="priority">Priority</option>
									<option value="weighted">Weighted</option>
								</select>
							</Field>
						</div>
						{pool.keys.map((key, j) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: Controlled key labels change as the user types.
							<div key={j} className="flex gap-2">
								<Field
									label={`Key ${j + 1} label`}
									error={fieldError(`key_pools[${i}].keys[${j}]`)}
								>
									<input
										className={inputClass}
										disabled={disabled}
										value={key.label}
										onChange={(e) =>
											setDoc((d) => ({
												...d,
												key_pools: (d.key_pools ?? []).map((p, x) =>
													x === i
														? {
																...p,
																keys: p.keys.map((k, y) =>
																	y === j ? { ...k, label: e.target.value } : k,
																),
															}
														: p,
												),
											}))
										}
									/>
								</Field>
								<Field label={`Key ${j + 1} weight`}>
									<input
										className={inputClass}
										type="number"
										min={1}
										max={1000}
										disabled={disabled}
										value={key.weight ?? ""}
										onChange={(e) =>
											setDoc((d) => ({
												...d,
												key_pools: (d.key_pools ?? []).map((p, x) =>
													x === i
														? {
																...p,
																keys: p.keys.map((k, y) =>
																	y === j
																		? {
																				...k,
																				weight:
																					e.target.value === ""
																						? undefined
																						: Number(e.target.value),
																			}
																		: k,
																),
															}
														: p,
												),
											}))
										}
									/>
								</Field>
								<Button
									size="sm"
									disabled={disabled || pool.keys.length <= 1}
									onClick={() =>
										setDoc((d) => ({
											...d,
											key_pools: (d.key_pools ?? []).map((p, x) =>
												x === i
													? { ...p, keys: p.keys.filter((_, y) => y !== j) }
													: p,
											),
										}))
									}
								>
									Remove key
								</Button>
							</div>
						))}
						<Button
							size="sm"
							disabled={
								disabled ||
								pool.keys.length >= view.limits.max_pool_keys_per_provider
							}
							onClick={() =>
								setDoc((d) => ({
									...d,
									key_pools: (d.key_pools ?? []).map((p, j) =>
										j === i ? { ...p, keys: [...p.keys, { label: "" }] } : p,
									),
								}))
							}
						>
							Add key to {pool.provider}
						</Button>
						<Button
							size="sm"
							disabled={disabled}
							onClick={() =>
								setDoc((d) => ({
									...d,
									key_pools: (d.key_pools ?? []).filter((_, j) => j !== i),
								}))
							}
						>
							Remove pool
						</Button>
					</section>
				))}
				<Button
					size="sm"
					disabled={disabled}
					onClick={() =>
						setDoc((d) => ({
							...d,
							key_pools: [
								...(d.key_pools ?? []),
								{ provider: "", strategy: "priority", keys: [{ label: "" }] },
							],
						}))
					}
				>
					Add key pool
				</Button>
				<p className="text-xs text-ink-3">
					Up to {view.limits.max_pool_keys_per_provider} keys per provider.
				</p>
			</Panel>
			<Panel
				title="Conditional rules"
				description="Match a request, then route it or split it between named arms."
			>
				{(doc.rules ?? []).map((rule, i) => {
					const source = rule.match.header
						? "header"
						: rule.match.metadata
							? "metadata"
							: "model";
					const split = rule.action.split;
					return (
						<section
							key={rule.id}
							className="space-y-3 border-t border-line pt-3"
							aria-label={`Rule ${i + 1}`}
						>
							<div className="grid gap-2 sm:grid-cols-3">
								<Field
									label={`Rule ${i + 1} name`}
									error={fieldError(`rules[${i}]`)}
								>
									<input
										className={inputClass}
										disabled={disabled}
										defaultValue={rule.id}
										onBlur={(e) => {
											const next = e.target.value.trim();
											if (
												(doc.rules ?? []).some(
													(r, j) => j !== i && r.id === next,
												)
											) {
												e.target.value = rule.id;
												return;
											}
											if (next !== rule.id) patchRule(i, { ...rule, id: next });
										}}
									/>
								</Field>
								<Field label="Match model">
									<input
										className={inputClass}
										disabled={disabled}
										value={rule.match.model}
										onChange={(e) =>
											patchRule(i, {
												...rule,
												match: { ...rule.match, model: e.target.value },
											})
										}
									/>
								</Field>
								<Field label="Match source">
									<select
										className={inputClass}
										disabled={disabled}
										value={source}
										onChange={(e) => {
											const { header: _h, metadata: _m, ...rest } = rule.match;
											const src = e.target.value;
											patchRule(i, {
												...rule,
												match: {
													...rest,
													...(src === "header"
														? { header: { name: "", equals: "" } }
														: src === "metadata"
															? { metadata: { key: "", equals: "" } }
															: {}),
												},
											});
										}}
									>
										<option value="model">Model only</option>
										<option value="header">Header</option>
										<option value="metadata">Metadata</option>
									</select>
								</Field>
							</div>
							{rule.match.header ? (
								<div className="grid gap-2 sm:grid-cols-2">
									<Field label="Header name">
										<input
											className={inputClass}
											disabled={disabled}
											value={rule.match.header.name}
											onChange={(e) =>
												patchRule(i, {
													...rule,
													match: {
														...rule.match,
														header: {
															...(rule.match.header ?? {
																name: "",
																equals: "",
															}),
															name: e.target.value,
														},
													},
												})
											}
										/>
									</Field>
									<Field
										label={
											rule.match.header.in
												? "Header values (comma separated)"
												: rule.match.header.prefix !== undefined
													? "Header prefix"
													: "Header equals"
										}
									>
										<input
											className={inputClass}
											disabled={disabled}
											value={
												rule.match.header.equals ??
												rule.match.header.prefix ??
												rule.match.header.in?.join(", ") ??
												""
											}
											onChange={(e) =>
												patchRule(i, {
													...rule,
													match: {
														...rule.match,
														header: rule.match.header?.in
															? {
																	name: rule.match.header.name,
																	in: e.target.value
																		.split(",")
																		.map((v) => v.trim()),
																}
															: rule.match.header?.prefix !== undefined
																? {
																		name: rule.match.header.name,
																		prefix: e.target.value,
																	}
																: {
																		name: rule.match.header?.name ?? "",
																		equals: e.target.value,
																	},
													},
												})
											}
										/>
									</Field>
								</div>
							) : null}
							{rule.match.metadata ? (
								<div className="grid gap-2 sm:grid-cols-2">
									<Field label="Metadata key">
										<input
											className={inputClass}
											disabled={disabled}
											value={rule.match.metadata.key}
											onChange={(e) =>
												patchRule(i, {
													...rule,
													match: {
														...rule.match,
														metadata: {
															...(rule.match.metadata ?? {
																key: "",
																equals: "",
															}),
															key: e.target.value,
														},
													},
												})
											}
										/>
									</Field>
									<Field
										label={
											rule.match.metadata.in
												? "Metadata values (comma separated)"
												: "Metadata equals"
										}
									>
										<input
											className={inputClass}
											disabled={disabled}
											value={
												rule.match.metadata.equals ??
												rule.match.metadata.in?.join(", ") ??
												""
											}
											onChange={(e) =>
												patchRule(i, {
													...rule,
													match: {
														...rule.match,
														metadata: rule.match.metadata?.in
															? {
																	key: rule.match.metadata.key,
																	in: e.target.value
																		.split(",")
																		.map((v) => v.trim()),
																}
															: {
																	key: rule.match.metadata?.key ?? "",
																	equals: e.target.value,
																},
													},
												})
											}
										/>
									</Field>
								</div>
							) : null}
							<Field label="Action">
								<select
									className={inputClass}
									disabled={disabled}
									value={split ? "split" : "route"}
									onChange={(e) =>
										patchRule(i, {
											...rule,
											action:
												e.target.value === "split"
													? {
															split: {
																sticky_by: [],
																on_missing_identity: "stable",
																arms: [
																	{ name: "A", route_to: "", bp: 5000 },
																	{ name: "B", route_to: "" },
																],
															},
														}
													: { route_to: "" },
										})
									}
								>
									<option value="route">Route to one model</option>
									<option value="split">Canary / A-B split</option>
								</select>
							</Field>
							{split ? (
								<>
									<Field label="Sticky source">
										<select
											className={inputClass}
											disabled={disabled || split.sticky_by.length > 1}
											value={
												split.sticky_by[0]?.startsWith("header:")
													? "header"
													: (split.sticky_by[0] ?? "")
											}
											onChange={(e) =>
												patchRule(i, {
													...rule,
													action: {
														split: {
															...split,
															sticky_by: e.target.value
																? [
																		e.target.value === "header"
																			? "header:"
																			: e.target.value,
																	]
																: [],
														},
													},
												})
											}
										>
											<option value="">No sticky source</option>
											<option value="end_user">End user</option>
											<option value="session">Session</option>
											<option value="key">API key</option>
											<option value="header">Header</option>
										</select>
									</Field>
									{split.sticky_by[0]?.startsWith("header:") ? (
										<Field label="Sticky header name">
											<input
												className={inputClass}
												disabled={disabled || split.sticky_by.length > 1}
												value={split.sticky_by[0].slice(7)}
												onChange={(e) =>
													patchRule(i, {
														...rule,
														action: {
															split: {
																...split,
																sticky_by: [`header:${e.target.value}`],
															},
														},
													})
												}
											/>
										</Field>
									) : null}
									{split.sticky_by.length > 1 ? (
										<p className="text-xs text-ink-3">
											This split has multiple sticky sources. They are
											preserved; change them through the API.
										</p>
									) : null}
									<Field label="When identity is missing">
										<select
											className={inputClass}
											disabled={disabled}
											value={split.on_missing_identity}
											onChange={(e) =>
												patchRule(i, {
													...rule,
													action: {
														split: {
															...split,
															on_missing_identity: e.target.value as
																| "stable"
																| "random"
																| "refuse",
														},
													},
												})
											}
										>
											<option value="stable">Stable</option>
											<option value="random">Random</option>
											<option value="refuse">Refuse</option>
										</select>
									</Field>
									{split.arms.map((arm, j) => (
										// biome-ignore lint/suspicious/noArrayIndexKey: Controlled arm names change as the user types.
										<div key={j} className="grid gap-2 sm:grid-cols-3">
											<Field label={`Arm ${j + 1} name`}>
												<input
													className={inputClass}
													disabled={disabled}
													value={arm.name}
													onChange={(e) =>
														patchRule(i, {
															...rule,
															action: {
																split: {
																	...split,
																	arms: split.arms.map((a, k) =>
																		k === j
																			? { ...a, name: e.target.value }
																			: a,
																	),
																},
															},
														})
													}
												/>
											</Field>
											<Field label={`Arm ${j + 1} route to`}>
												<input
													className={inputClass}
													disabled={disabled}
													value={arm.route_to}
													onChange={(e) =>
														patchRule(i, {
															...rule,
															action: {
																split: {
																	...split,
																	arms: split.arms.map((a, k) =>
																		k === j
																			? { ...a, route_to: e.target.value }
																			: a,
																	),
																},
															},
														})
													}
												/>
											</Field>
											{j < split.arms.length - 1 ? (
												<Field label={`Arm ${j + 1} percent`}>
													<input
														className={inputClass}
														type="number"
														min={0}
														max={100}
														disabled={disabled}
														value={(arm.bp ?? 0) / 100}
														onChange={(e) =>
															patchRule(i, {
																...rule,
																action: {
																	split: {
																		...split,
																		arms: split.arms.map((a, k) =>
																			k === j
																				? {
																						...a,
																						bp: Math.round(
																							Number(e.target.value) * 100,
																						),
																					}
																				: a,
																		),
																	},
																},
															})
														}
													/>
												</Field>
											) : (
												<p className="text-sm text-ink-2">Remainder</p>
											)}
										</div>
									))}
									<Button
										size="sm"
										disabled={
											disabled ||
											split.arms.length >= view.limits.rules.max_arms
										}
										onClick={() =>
											patchRule(i, {
												...rule,
												action: {
													split: {
														...split,
														arms: [
															...split.arms.slice(0, -1),
															{
																...(split.arms.at(-1) ?? {
																	name: "",
																	route_to: "",
																}),
																bp: 0,
															},
															{ name: "", route_to: "" },
														],
													},
												},
											})
										}
									>
										Add split arm
									</Button>
								</>
							) : (
								<Field label="Route to">
									<input
										className={inputClass}
										disabled={disabled}
										value={rule.action.route_to ?? ""}
										onChange={(e) =>
											patchRule(i, {
												...rule,
												action: { route_to: e.target.value },
											})
										}
									/>
								</Field>
							)}
							<Button
								size="sm"
								disabled={disabled}
								onClick={() =>
									setDoc((d) => ({
										...d,
										rules: (d.rules ?? []).filter((_, j) => j !== i),
									}))
								}
							>
								Remove rule
							</Button>
						</section>
					);
				})}
				<Button
					size="sm"
					disabled={
						disabled || (doc.rules ?? []).length >= view.limits.rules.max_rules
					}
					onClick={() =>
						setDoc((d) => {
							let n = 1;
							while ((d.rules ?? []).some((r) => r.id === `Rule ${n}`)) n++;
							return {
								...d,
								rules: [
									...(d.rules ?? []),
									{
										id: `Rule ${n}`,
										wires: ["chat", "responses"],
										match: { model: "" },
										action: { route_to: "" },
									},
								],
							};
						})
					}
				>
					Add rule
				</Button>
				<p className="text-xs text-ink-3">
					Up to {view.limits.rules.max_rules} rules and{" "}
					{view.limits.rules.max_arms} split arms.
				</p>
			</Panel>
			<Panel
				title="Circuit breaker"
				description="Override the workspace's failure count and cooldown."
			>
				{doc.breaker ? (
					<div className="grid gap-3 sm:grid-cols-2">
						<Field
							label="Consecutive failures"
							error={fieldError("breaker.consecutive_failures")}
						>
							<input
								className={inputClass}
								type="number"
								min={view.limits.breaker.consecutive_failures_min}
								max={view.limits.breaker.consecutive_failures_max}
								disabled={disabled}
								value={doc.breaker.consecutive_failures}
								onChange={(e) =>
									setDoc((d) => ({
										...d,
										breaker: {
											...(d.breaker ?? {
												consecutive_failures: 1,
												cooldown_secs: 1,
											}),
											consecutive_failures: Number(e.target.value),
										},
									}))
								}
							/>
						</Field>
						<Field
							label="Cooldown seconds"
							error={fieldError("breaker.cooldown_secs")}
						>
							<input
								className={inputClass}
								type="number"
								min={view.limits.breaker.cooldown_secs_min}
								max={view.limits.breaker.cooldown_secs_max}
								disabled={disabled}
								value={doc.breaker.cooldown_secs}
								onChange={(e) =>
									setDoc((d) => ({
										...d,
										breaker: {
											...(d.breaker ?? {
												consecutive_failures: 1,
												cooldown_secs: 1,
											}),
											cooldown_secs: Number(e.target.value),
										},
									}))
								}
							/>
						</Field>
						<Button
							size="sm"
							disabled={disabled}
							onClick={() =>
								setDoc((d) => {
									const { breaker: _breaker, ...rest } = d;
									return rest;
								})
							}
						>
							Use default breaker
						</Button>
					</div>
				) : (
					<Button
						size="sm"
						disabled={disabled}
						onClick={() =>
							setDoc((d) => ({
								...d,
								breaker: {
									consecutive_failures:
										view.limits.breaker.consecutive_failures_min,
									cooldown_secs: view.limits.breaker.cooldown_secs_min,
								},
							}))
						}
					>
						Set breaker override
					</Button>
				)}
				<p className="text-xs text-ink-3">
					Failures: {view.limits.breaker.consecutive_failures_min}–
					{view.limits.breaker.consecutive_failures_max}; cooldown:{" "}
					{view.limits.breaker.cooldown_secs_min}–
					{view.limits.breaker.cooldown_secs_max} seconds.
				</p>
			</Panel>
			{invalid ? (
				<p role="alert" className="text-sm text-danger-ink">
					{invalid}
				</p>
			) : null}
			<RefusalNote error={write.error} fieldOnly />
			{remoteChanged ? (
				<p role="alert" className="text-sm text-danger-ink">
					Routing changed while you were editing. Reload it before saving.
				</p>
			) : null}
			<p className="text-sm text-ink-2">
				{count} pending {count === 1 ? "change" : "changes"}
			</p>
			<WhyDisabled reason={reason} />
			{conflict || remoteChanged ? (
				<Button
					size="sm"
					disabled={reloading}
					onClick={async () => {
						setReloading(true);
						try {
							const latest = await onReload();
							if (latest) {
								baseline.current = { doc: latest.doc, version: latest.version };
								setDoc(latest.doc);
								write.reset();
							}
						} finally {
							setReloading(false);
						}
					}}
				>
					Reload latest routing and discard edits
				</Button>
			) : null}
			<Button
				variant="primary"
				size="sm"
				disabled={disabled || !!invalid || count === 0}
				onClick={() => write.mutate(doc)}
			>
				{write.isPending ? "Saving…" : "Save routing"}
			</Button>
			{write.isSuccess ? (
				<output className="text-sm text-ok-ink">Routing saved</output>
			) : null}
		</div>
	);
}

export function RoutingEditor() {
	const query = useControlQuery<RoutingView>("routing");
	const { allowed, reason } = useCan("edit_policies");
	if (query.isError && query.error.status === 403)
		return (
			<Panel title="Routing unavailable">
				<EmptyNote>
					Only workspace admins can view and change routing.
				</EmptyNote>
			</Panel>
		);
	if (query.isError && query.error.status === 404)
		return (
			<Panel title="Routing unavailable">
				<EmptyNote>This gateway does not serve the routing route.</EmptyNote>
			</Panel>
		);
	return (
		<Boundary query={query} resource="routing" rows={4}>
			{(view) =>
				view.valid &&
				view.doc &&
				typeof view.doc === "object" &&
				!Array.isArray(view.doc) &&
				view.limits ? (
					<RoutingForm
						view={view}
						roleAllowed={allowed}
						roleReason={reason}
						onReload={() =>
							query.refetch().then((result) => result.data ?? null)
						}
					/>
				) : (
					<Panel title="Routing document unavailable">
						<EmptyNote>
							The saved routing document cannot be opened safely in this editor.
							Correct it through the API, then reload this page.
						</EmptyNote>
					</Panel>
				)
			}
		</Boundary>
	);
}
