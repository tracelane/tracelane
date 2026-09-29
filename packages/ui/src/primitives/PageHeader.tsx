import type { ReactNode } from "react";
export function PageHeader({
	title,
	id,
	description,
	actions,
	breadcrumb,
}: {
	title: ReactNode;
	id?: string;
	description?: ReactNode;
	actions?: ReactNode;
	breadcrumb?: ReactNode;
}) {
	return (
		<div data-page-header className="mb-6 min-w-0 space-y-3">
			{breadcrumb}
			<div className="flex flex-wrap items-start justify-between gap-4">
				<div className="min-w-0">
					<h1 id={id} className="t-h1 break-words">
						{title}
					</h1>
					{description && (
						<div className="mt-2 max-w-3xl text-sm text-ink-2">
							{description}
						</div>
					)}
				</div>
				{actions && (
					<div className="flex flex-wrap items-center gap-2">{actions}</div>
				)}
			</div>
		</div>
	);
}
