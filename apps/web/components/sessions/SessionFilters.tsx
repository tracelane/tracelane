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

import { cn } from "@tracelanedev/ui";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

const STATUS = [
	{ v: "", l: "All" },
	{ v: "error", l: "Errored" },
	{ v: "ok", l: "Clean" },
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
			<div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
				{STATUS.map((o) => (
					<button
						key={o.v || "all"}
						type="button"
						onClick={() => setParam("status", o.v)}
						className={cn(
							"rounded-md px-2.5 py-1 text-[12.5px] transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal",
							status === o.v
								? "bg-accent-soft text-ink"
								: "text-ink-2 hover:text-ink",
						)}
					>
						{o.l}
					</button>
				))}
			</div>
			<input
				value={model}
				onChange={(e) => setModel(e.target.value)}
				placeholder="model (exact)…"
				aria-label="Filter sessions by model"
				className="h-8 w-44 rounded-lg border border-line bg-surface px-2.5 text-[13px] text-ink outline-none placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
			/>
		</div>
	);
}
