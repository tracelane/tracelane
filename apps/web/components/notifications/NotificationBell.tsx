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

export function NotificationBell() {
	const [status, setStatus] = useState<Status>("loading");
	const [items, setItems] = useState<Notification[]>([]);
	const [unread, setUnread] = useState(0);
	const [open, setOpen] = useState(false);

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
		<div className="relative">
			<button
				type="button"
				onClick={() => setOpen((v) => !v)}
				aria-label={
					showBadge ? `Notifications, ${unread} unread` : "Notifications"
				}
				aria-expanded={open}
				className="relative rounded-lg border border-line px-2 py-1 text-[13px]"
			>
				<span aria-hidden="true">🔔</span>
				{showBadge && <span className="ml-1 font-medium">{unread}</span>}
			</button>

			{open && (
				<div className="absolute right-0 z-50 mt-1 w-96 rounded-lg border border-line bg-surface-2 p-3 shadow-lg">
					<div className="mb-2 flex items-center justify-between">
						<span className="font-medium">Notifications</span>
						<span className="text-[12px] text-ink-3">
							Shared with your workspace
						</span>
					</div>

					{status === "loading" && (
						<p className="text-[13px] text-ink-3">Loading…</p>
					)}

					{/* The whole point of the error state: say it, never render an
					    empty inbox for a failed fetch. */}
					{status === "error" && (
						<p role="alert" className="text-[13px] text-ink-2">
							Couldn&apos;t load notifications. This is a loading problem, not
							an empty inbox.
						</p>
					)}

					{status === "ok" && items.length === 0 && (
						<p className="text-[13px] text-ink-3">Nothing to catch up on.</p>
					)}

					{status === "ok" && items.length > 0 && (
						<ul className="space-y-2">
							{items.map((n) => (
								<li
									key={n.id}
									className="border-b border-line pb-2 last:border-b-0"
								>
									<div className="flex items-start gap-2">
										<span aria-hidden="true">{kindGlyph(n.kind)}</span>
										<div className="min-w-0 flex-1">
											<div className="text-[13px] font-medium">
												{/* Unread is marked by a word, not only by weight
												    or colour. */}
												{n.read_at === null && (
													<span className="mr-1 text-[11px] uppercase">
														new
													</span>
												)}
												{n.title}
											</div>
											{n.body && (
												<div className="text-[12px] text-ink-3">{n.body}</div>
											)}
											<div className="mt-0.5 flex items-center gap-2 text-[12px] text-ink-3">
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
