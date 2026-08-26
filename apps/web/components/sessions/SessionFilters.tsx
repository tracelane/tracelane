/**
 * SessionFilters — status + model filter controls for the /sessions list.
 *
 * URL-driven (shareable, back-button-able): each control writes a `?status=` /
 * `?model=` param and the server component re-fetches. Composes with the shared
 * <RangeControl> (which owns `?range=`) — both merge existing params, so the
 * date range, status, and model filters coexist. Only the dimensions the
 * gateway `/v1/sessions` endpoint genuinely filters on are rendered — no dead
 * controls (status→HAVING, model→WHERE model = ?).
 */
"use client";

import { SegmentedControl } from "@tracelanedev/ui";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

const STATUS = [
	{ value: "", label: "All" },
	{ value: "error", label: "Errored" },
	{ value: "ok", label: "Clean" },
] as const;

export function SessionFilters() {
	const router = useRouter();
	const pathname = usePathname();
	const sp = useSearchParams();
	const status = sp.get("status") ?? "";
	const urlModel = sp.get("model") ?? "";
	const [model, setModel] = useState(urlModel);

	// Resync the input when `?model=` changes from outside (back/forward, an
	// external clear). Without this the debounce below fires with the stale local
	// value and silently re-applies it — reverting the navigation.
	useEffect(() => {
		setModel(urlModel);
	}, [urlModel]);

	const setParam = useCallback(
		(key: string, value: string) => {
			const next = new URLSearchParams(sp.toString());
			if (value) next.set(key, value);
			else next.delete(key);
			const qs = next.toString();
			router.replace(qs ? `${pathname}?${qs}` : pathname);
		},
		[sp, pathname, router],
	);

	// debounce the model input → URL (exact match, per the gateway `model = ?`).
	useEffect(() => {
		const id = setTimeout(() => {
			if ((sp.get("model") ?? "") !== model.trim())
				setParam("model", model.trim());
		}, 350);
		return () => clearTimeout(id);
	}, [model, setParam, sp]);

	return (
		<div className="inline-flex flex-wrap items-center gap-2">
			{/* The shared <SegmentedControl> — literally the same control as the traces
			    FilterBar's status segment, which is the point: this file used to
			    hand-roll its own copy and the two surfaces had drifted apart once
			    already. */}
			<SegmentedControl
				label="Session status"
				value={status}
				options={STATUS}
				onChange={(v) => setParam("status", v)}
			/>
			<input
				value={model}
				onChange={(e) => setModel(e.target.value)}
				placeholder="model (exact)…"
				aria-label="Filter sessions by model"
				// `rounded-lg` (`--radius-control`, 8px) — the same as the traces FilterBar's
				// model input, which is literally the same control on the sibling surface.
				// It was `rounded-sm` (4px), half the control radius.
				className="h-8 w-44 rounded-lg border border-line bg-surface px-2.5 text-sm text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
			/>
		</div>
	);
}
