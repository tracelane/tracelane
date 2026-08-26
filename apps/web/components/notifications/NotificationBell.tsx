"use client";

/**
 * DSH-01 — the header bell: what happened while nobody was looking.
 *
 * **Four states, all rendered:**
 *   loading  — no badge, no claim either way
 *   empty    — "Nothing to catch up on." and **no badge at all, never a 0**
 *   items    — unread count, newest first
 *   error    — "Couldn't load notifications" IN THE PANEL, and the bell shows
 *              NO badge
 *
 * The error state is the one that matters. A broken inbox and an empty inbox
 * look identical unless the broken one says so, and an inbox that quietly shows
 * nothing is indistinguishable from a quiet week — the §18 shape. So a fetch
 * failure never renders as "you're all caught up".
 *
 * Read state is TENANT-WIDE (one row, one read mark, shared by the workspace).
 * The panel says so rather than letting a user assume it is theirs alone.
 */

import { absoluteDate } from "@/lib/format-date";
import { useDismiss } from "@/lib/use-dismiss";
import Link from "next/link";
import { useEffect, useState } from "react";

type Notification = {
	id: string;
	kind: "quota" | "alert" | "promotion";
	title: string;
	body: string;
	severity: "info" | "warning" | "critical";
	link: string;
	read_at: string | null;
	created_at: string;
};

type Status = "loading" | "ok" | "error";

/** Icon per kind — paired with text everywhere, never the only signal. */
function kindGlyph(k: Notification["kind"]): string {
	return k === "quota" ? "▣" : k === "alert" ? "⚑" : "✓";
}

/**
 * The bell itself, as a monochrome outline drawn in `currentColor`.
 *
 * IT WAS THE 🔔 EMOJI. That is a full-colour bitmap glyph rendered by the
 * platform's emoji font — orange and yellow on macOS, a different orange on
 * Windows, a third on Android — sitting in the top bar of a system whose first
 * rule is that icons are monochrome and nothing decorative carries a hue. It was
 * also the one control in the bar the app could not restyle, because a font
 * decides its colour. An inline SVG matches every other icon in the chrome
 * (`nav-config.tsx`, `ThemeToggle`), adds no dependency, and inherits `--ink`.
 */
function BellIcon() {
	return (
		<svg
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
			<path d="M13.73 21a2 2 0 0 1-3.46 0" />
		</svg>
	);
}

export function NotificationBell() {
	const [status, setStatus] = useState<Status>("loading");
	const [items, setItems] = useState<Notification[]>([]);
	const [unread, setUnread] = useState(0);
	const [open, setOpen] = useState(false);

	// Escape and click-outside. The panel used to be closable ONLY by clicking the
	// bell again — a popover the rest of the page could not dismiss. The ref wraps
	// the trigger too, so pressing the bell to close is not read as an outside
	// click that would close and instantly re-open it.
	const popoverRef = useDismiss<HTMLDivElement>(open, () => setOpen(false));

	useEffect(() => {
		let live = true;
		(async () => {
			try {
				const res = await fetch("/api/notifications");
				if (!res.ok) throw new Error(String(res.status));
				const data = (await res.json()) as {
					notifications: Notification[];
					unread: number;
				};
				if (!live) return;
				setItems(data.notifications ?? []);
				setUnread(data.unread ?? 0);
				setStatus("ok");
			} catch {
				if (live) setStatus("error");
			}
		})();
		return () => {
			live = false;
		};
	}, []);

	async function markRead(id: string) {
		// Optimistic, but only for a state we can restore: on failure the row
		// goes back to unread rather than silently claiming it was marked.
		const before = items;
		const beforeUnread = unread;
		setItems((xs) =>
			xs.map((x) =>
				x.id === id ? { ...x, read_at: new Date().toISOString() } : x,
			),
		);
		setUnread((n) => Math.max(0, n - 1));
		const res = await fetch(`/api/notifications/${id}/read`, {
			method: "POST",
		}).catch(() => null);
		if (!res || (!res.ok && res.status !== 404)) {
			setItems(before);
			setUnread(beforeUnread);
		}
	}

	// A badge is shown ONLY for a real positive count. Never "0", and never
	// while loading or errored — a badge is a claim, and we only make it when
	// we know it is true.
	const showBadge = status === "ok" && unread > 0;

	return (
		<div className="relative" ref={popoverRef}>
			{/*
			 * The trigger is now the same 36px `--surface-2` chip as the theme toggle
			 * beside it — the brief's container-chip shape for an icon, and the fix
			 * for a top-bar cluster that carried three controls at three heights.
			 *
			 * THE COUNT IS STILL A NUMBER, NOT A DOT. A bare dot would say "something
			 * happened" where the component knows how many, and the count is already
			 * load-bearing in the accessible name. It moves to a corner badge in the
			 * theme-flipped `--action` / `--action-on` pair (ink chip + light label in
			 * light, light chip + ink label in dark) so it reads at 11px against the
			 * chip in both themes without introducing a colour. The badge renders ONLY
			 * for a real positive count — see `showBadge` above.
			 */}
			<button
				type="button"
				onClick={() => setOpen((v) => !v)}
				aria-label={
					showBadge ? `Notifications, ${unread} unread` : "Notifications"
				}
				aria-expanded={open}
				className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-surface-2 text-ink transition-colors hover:bg-surface-3"
			>
				<BellIcon />
				{showBadge && (
					<span
						aria-hidden="true"
						className="-top-0.5 -right-0.5 absolute flex min-w-4 items-center justify-center rounded-full bg-action px-1 font-medium text-2xs text-action-on tabular-nums"
					>
						{unread}
					</span>
				)}
			</button>

			{open && (
				/*
				 * The panel is a floating CARD: `--surface` at `--radius-card` under
				 * `--shadow-overlay`. It was `--surface-2` — the inert WELL token, the
				 * one chips and tracks are painted with — at Tailwind's own radius and
				 * shadow scale, so a popover claiming to sit above the page wore the
				 * material of a recess inside it. In dark that was also literally
				 * backwards: the well (#1c1d20) is lighter than the card (#151619), so
				 * the panel read as a lifted tray rather than as a sheet.
				 */
				<div className="absolute right-0 z-50 mt-2 w-96 rounded-[var(--radius-card)] border border-line bg-surface p-4 shadow-[var(--shadow-overlay)]">
					<div className="mb-3 flex items-center justify-between">
						<span className="font-medium text-ink">Notifications</span>
						<span className="text-xs text-ink-3">
							Shared with your workspace
						</span>
					</div>

					{status === "loading" && (
						<p className="text-sm text-ink-3">Loading…</p>
					)}

					{/* The whole point of the error state: say it, never render an
					    empty inbox for a failed fetch. */}
					{status === "error" && (
						<p role="alert" className="text-sm text-ink-2">
							Couldn&apos;t load notifications. This is a loading problem, not
							an empty inbox.
						</p>
					)}

					{status === "ok" && items.length === 0 && (
						<p className="text-sm text-ink-3">Nothing to catch up on.</p>
					)}

					{status === "ok" && items.length > 0 && (
						<ul className="space-y-2">
							{items.map((n) => (
								<li
									key={n.id}
									className="border-b border-line pb-2 last:border-b-0"
								>
									<div className="flex items-start gap-2">
										{/* The kind glyph on a `--surface-2` chip — the brief's
										    container shape for an icon. Text glyphs, so they are
										    monochrome already and inherit secondary ink. */}
										<span
											aria-hidden="true"
											className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-[var(--radius-control)] bg-surface-2 text-2xs text-ink-2"
										>
											{kindGlyph(n.kind)}
										</span>
										<div className="min-w-0 flex-1">
											<div className="font-medium text-ink text-sm">
												{/* Unread is marked by a word, not only by weight
												    or colour. The word takes the metric-label
												    treatment (11px/600/0.08em small caps) so it reads
												    as a marker rather than as a shouted word in the
												    title's own size. */}
												{n.read_at === null && (
													<span className="mr-1.5 text-2xs uppercase tracking-[0.08em] text-ink-3">
														new
													</span>
												)}
												{n.title}
											</div>
											{n.body && (
												<div className="text-xs text-ink-3">{n.body}</div>
											)}
											<div className="mt-0.5 flex items-center gap-2 text-xs text-ink-3">
												<span>{absoluteDate(n.created_at)}</span>
												{n.link && (
													<Link className="underline" href={n.link}>
														Open
													</Link>
												)}
												{n.read_at === null && (
													<button
														type="button"
														onClick={() => markRead(n.id)}
														className="underline"
													>
														Mark read
													</button>
												)}
											</div>
										</div>
									</div>
								</li>
							))}
						</ul>
					)}
				</div>
			)}
		</div>
	);
}
