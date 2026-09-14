"use client";

/**
 * /dashboards/new — create a new dashboard.
 * Client component: form state + redirect.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function NewDashboardPage() {
	const router = useRouter();
	const [name, setName] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [creating, setCreating] = useState(false);

	async function handleCreate(e: React.FormEvent) {
		e.preventDefault();
		if (!name.trim()) {
			setError("Name is required");
			return;
		}
		setCreating(true);
		setError(null);
		try {
			const res = await fetch("/api/dashboards", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: name.trim() }),
			});
			if (!res.ok) {
				const body = (await res.json()) as { error?: string };
				setError(body.error ?? "Failed to create dashboard");
				return;
			}
			const created = (await res.json()) as { id: string };
			router.push(`/dashboards/${created.id}`);
		} catch {
			setError("Network error — try again");
		} finally {
			setCreating(false);
		}
	}

	return (
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			<header>
				<h1 className="t-h1">New dashboard</h1>
				<p className="mt-2 text-sm text-ink-2">
					Give it a name — you can rename it any time.
				</p>
			</header>
			<div className="stat-tile max-w-lg p-6">
				<form onSubmit={handleCreate} className="flex flex-col gap-4">
					<div className="flex flex-col gap-1.5">
						<label htmlFor="dashboard-name" className="t-metric-label">
							Name
						</label>
						<input
							id="dashboard-name"
							type="text"
							value={name}
							onChange={(e) => setName(e.target.value)}
							placeholder="My dashboard"
							maxLength={60}
							className="rounded-[var(--radius-control)] border border-line bg-surface px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-action"
						/>
						{error && <p className="text-xs text-danger-ink">{error}</p>}
					</div>
					<div className="flex items-center justify-end gap-3">
						<button
							type="button"
							onClick={() => router.back()}
							className="rounded-[var(--radius-control)] px-4 py-2 text-sm text-ink-2 hover:bg-surface-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						>
							Cancel
						</button>
						<button
							type="submit"
							disabled={creating || !name.trim()}
							className="rounded-[var(--radius-control)] bg-action px-4 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90 disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						>
							{creating ? "Creating…" : "Create dashboard"}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}
