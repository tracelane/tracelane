/**
 * Route-level loading skeleton for `/s/[token]` — shown instantly on
 * navigation while the unauthenticated gateway fetch resolves. No workspace
 * name or trace data is known yet, so this is generic chrome only.
 */

import { Logo, Skeleton } from "@tracelanedev/ui";

export default function Loading() {
	return (
		<div className="flex min-h-screen flex-col">
			<header className="flex items-center justify-between border-b border-line px-6 py-4">
				<Logo withWordmark height={22} />
				<Skeleton className="h-4 w-56" />
			</header>
			<div className="mx-auto w-full max-w-6xl flex-1 p-6">
				<Skeleton className="h-7 w-64" />
				<Skeleton className="mt-2 h-5 w-40" />
				<div className="mt-6 space-y-1.5">
					<Skeleton className="h-9 w-[92%]" />
					<Skeleton className="h-9 w-[83%]" />
					<Skeleton className="h-9 w-[74%]" />
				</div>
			</div>
		</div>
	);
}
