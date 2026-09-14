/**
 * RangeControl — the ONE time-range control (DSH-11 §3b). Presets from the
 * shared `PRESETS` list plus a **Custom** window, driving a server-rendered page
 * through the shared URL grammar (`?range=` or `?since=&until=`).
 *
 * Extends the control the app already had rather than inventing a second one:
 * the optimistic pill, the `useTransition` that keeps the current view on screen,
 * the top progress bar and the hover-only prefetch are unchanged (the header of
 * the previous revision carried the measurements that set them — 33 gateway
 * subrequests from a mount-time prefetch of every preset — and they stand).
 *
 * WHAT IS NEW. A `Custom` option opens a small popover with two UTC
 * `datetime-local` fields. Apply writes `since`/`until` and DELETES `range`;
 * choosing a preset DELETES `since`/`until` — the two forms are mutually
 * exclusive, the rule `app/traces/filter-params.ts` states for the traces bar,
 * now applied to every page. The popover is a plain positioned card: no portal,
 * no blur, one overlay shadow.
 */
"use client";

import { useNavProgress } from "@/components/NavProgress";
import {
	PRESETS,
	type Preset,
	formatWindowUtc,
	parseInstant,
} from "@/lib/metrics/time-range";
import { SegmentedControl } from "@tracelanedev/ui";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useId, useRef, useState, useTransition } from "react";

const CUSTOM = "custom" as const;
type Value = Preset | typeof CUSTOM;

const OPTIONS: readonly { value: Value; label: string; title?: string }[] = [
	...PRESETS.map((p) => ({
		value: p.value,
		label: p.label,
		title: `last ${p.long}`,
	})),
	{ value: CUSTOM, label: "Custom", title: "An absolute window, in UTC" },
];

/** `datetime-local` wants `YYYY-MM-DDTHH:MM` in the field's own zone; we show UTC. */
function toLocalInput(ms: number): string {
	const d = new Date(ms);
	const p = (n: number) => String(n).padStart(2, "0");
	return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}

/**
 * @param defaultPreset the preset a page treats as its no-param default, so the
 *   active pill matches the data window. Sessions uses "30d"; most keep "24h".
 */
export function RangeControl({
	defaultPreset = "24h",
	defaultRange,
}: {
	defaultPreset?: Preset;
	/** @deprecated use `defaultPreset` — kept for one release so no caller breaks. */
	defaultRange?: string;
} = {}) {
	const router = useRouter();
	const pathname = usePathname();
	const sp = useSearchParams();
	const [isPending, startTransition] = useTransition();
	const { setPending } = useNavProgress();
	const fallback: Preset =
		defaultRange && PRESETS.some((p) => p.value === defaultRange)
			? (defaultRange as Preset)
			: defaultPreset;

	const urlSince = sp.get("since");
	const urlUntil = sp.get("until");
	const urlRange = sp.get("range");
	const committed: Value = urlSince
		? CUSTOM
		: urlRange && PRESETS.some((p) => p.value === urlRange)
			? (urlRange as Preset)
			: fallback;

	// Optimistic selection — reset when the committed value changes (render-time
	// state reset, no effect).
	const [optimistic, setOptimistic] = useState<Value | null>(null);
	const [seen, setSeen] = useState<string | null>(null);
	const urlKey = `${committed}|${urlSince ?? ""}|${urlUntil ?? ""}`;
	if (seen !== urlKey) {
		setSeen(urlKey);
		setOptimistic(null);
	}
	const active = optimistic ?? committed;

	const [open, setOpen] = useState(false);
	const sinceMs = parseInstant(urlSince) ?? Date.now() - 3 * 3_600_000;
	const untilMs = parseInstant(urlUntil) ?? Date.now();
	const [from, setFrom] = useState(() => toLocalInput(sinceMs));
	const [to, setTo] = useState(() => toLocalInput(untilMs));
	const [error, setError] = useState<string | null>(null);
	const popRef = useRef<HTMLDivElement>(null);
	const formId = useId();

	useEffect(() => {
		setPending(isPending);
	}, [isPending, setPending]);

	// Close on outside click / Escape.
	useEffect(() => {
		if (!open) return;
		const onDown = (e: MouseEvent) => {
			if (popRef.current && !popRef.current.contains(e.target as Node))
				setOpen(false);
		};
		const onKey = (e: globalThis.KeyboardEvent) => {
			if (e.key === "Escape") setOpen(false);
		};
		document.addEventListener("mousedown", onDown);
		document.addEventListener("keydown", onKey);
		return () => {
			document.removeEventListener("mousedown", onDown);
			document.removeEventListener("keydown", onKey);
		};
	}, [open]);

	const hrefForPreset = (v: Preset) => {
		const p = new URLSearchParams(sp.toString());
		p.set("range", v);
		p.delete("since");
		p.delete("until");
		p.delete("cursor");
		return `${pathname}?${p.toString()}`;
	};

	const choose = (v: Value) => {
		if (v === CUSTOM) {
			setFrom(toLocalInput(sinceMs));
			setTo(toLocalInput(untilMs));
			setError(null);
			setOpen(true);
			return;
		}
		if (v === active) return;
		setOpen(false);
		setOptimistic(v);
		startTransition(() => router.push(hrefForPreset(v)));
	};

	const apply = () => {
		// The fields are labelled UTC and read as UTC: append `Z`.
		const a = parseInstant(`${from}:00Z`);
		const b = parseInstant(`${to}:00Z`);
		if (a === null || b === null) {
			setError("Enter both times (UTC).");
			return;
		}
		if (!(b > a)) {
			setError("The end must be after the start.");
			return;
		}
		const p = new URLSearchParams(sp.toString());
		p.set("since", new Date(a).toISOString());
		p.set("until", new Date(b).toISOString());
		p.delete("range");
		p.delete("cursor");
		setError(null);
		setOpen(false);
		setOptimistic(CUSTOM);
		startTransition(() => router.push(`${pathname}?${p.toString()}`));
	};

	return (
		<div className="relative inline-flex flex-col items-end gap-1">
			<SegmentedControl<Value>
				label="Time range"
				value={active}
				options={OPTIONS}
				pending={isPending}
				onChange={choose}
				onOptionHover={(v) => {
					if (v !== CUSTOM) router.prefetch(hrefForPreset(v));
				}}
			/>
			{active === CUSTOM && urlSince && (
				<span
					className="font-mono text-2xs text-ink-3"
					style={{ fontVariantNumeric: "tabular-nums" }}
				>
					{formatWindowUtc(sinceMs, untilMs)}
				</span>
			)}
			{open && (
				<div
					ref={popRef}
					// biome-ignore lint/a11y/useSemanticElements: a positioned popover beside the control, not a modal — `<dialog>` carries top-layer/modal semantics and its own positioning, neither of which this is.
					role="dialog"
					aria-label="Custom time range (UTC)"
					className="absolute right-0 top-full z-40 mt-2 w-72 rounded-[var(--radius-card)] border border-line bg-surface p-3 text-sm shadow-[var(--shadow-overlay)]"
				>
					<p className="t-metric-label mb-2">Custom window · UTC</p>
					<label
						htmlFor={`${formId}-from`}
						className="block text-2xs text-ink-3"
					>
						From
					</label>
					<input
						id={`${formId}-from`}
						type="datetime-local"
						value={from}
						onChange={(e) => setFrom(e.target.value)}
						className="mb-2 w-full rounded-[var(--radius-control)] border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-ink"
					/>
					<label htmlFor={`${formId}-to`} className="block text-2xs text-ink-3">
						To
					</label>
					<input
						id={`${formId}-to`}
						type="datetime-local"
						value={to}
						onChange={(e) => setTo(e.target.value)}
						className="mb-2 w-full rounded-[var(--radius-control)] border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-ink"
					/>
					{error && <p className="mb-2 text-2xs text-danger-ink">{error}</p>}
					<div className="flex items-center justify-between gap-2">
						<span className="text-2xs text-ink-3">up to 30 days wide</span>
						<div className="flex gap-1.5">
							<button
								type="button"
								onClick={() => setOpen(false)}
								className="rounded-[var(--radius-control)] px-2 py-1 text-xs text-ink-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
							>
								Cancel
							</button>
							<button
								type="button"
								onClick={apply}
								className="rounded-[var(--radius-control)] bg-ink px-2.5 py-1 text-xs font-medium text-ink-inverse focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
							>
								Apply
							</button>
						</div>
					</div>
				</div>
			)}
		</div>
	);
}

export const DEFAULT_RANGE = "24h";
