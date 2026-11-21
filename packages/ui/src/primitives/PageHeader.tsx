"use client";
import { type ReactNode, useId, useState } from "react";

/**
 * Page title, optional description and actions.
 *
 * On a phone the description sits behind an "About this page" info button so the
 * page's content starts above the fold; from `sm` up it is always shown.
 * A caveat the reader must never miss (what the page cannot see, a plan limit)
 * goes in `note`, which is always visible.
 */
export function PageHeader({
	title,
	id,
	description,
	note,
	actions,
	breadcrumb,
}: {
	title: ReactNode;
	id?: string;
	description?: ReactNode;
	note?: ReactNode;
	actions?: ReactNode;
	breadcrumb?: ReactNode;
}) {
	const [open, setOpen] = useState(false);
	const descId = useId();
	return (
		<div data-page-header className="mb-6 min-w-0 space-y-3">
			{breadcrumb}
			<div className="flex flex-wrap items-start justify-between gap-4">
				<div className="min-w-0">
					<div className="flex items-start gap-2">
						<h1 id={id} className="t-h1 break-words">
							{title}
						</h1>
						{description && (
							<button
								type="button"
								aria-label="About this page"
								aria-expanded={open}
								aria-controls={open ? descId : undefined}
								onClick={() => setOpen((v) => !v)}
								className="relative mt-1 inline-flex h-6 w-6 shrink-0 after:absolute after:-inset-2.5 after:content-[''] items-center justify-center rounded-full border border-line text-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring sm:hidden"
							>
								<svg
									aria-hidden="true"
									viewBox="0 0 16 16"
									className="h-3.5 w-3.5"
									fill="currentColor"
								>
									<circle cx="8" cy="4.5" r="1.1" />
									<rect x="7.1" y="6.8" width="1.8" height="5.6" rx=".9" />
								</svg>
							</button>
						)}
					</div>
					{description && (
						<div
							id={descId}
							data-open={open || undefined}
							className="mt-2 hidden max-w-3xl text-sm text-ink-2 data-[open]:block sm:block"
						>
							{description}
						</div>
					)}
					{note && (
						<div className="mt-2 max-w-3xl text-sm text-ink-2">{note}</div>
					)}
				</div>
				{actions && (
					<div className="flex flex-wrap items-center gap-2">{actions}</div>
				)}
			</div>
		</div>
	);
}
