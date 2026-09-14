/**
 * `/s/[token]` 404 — rendered when `page.tsx` calls `notFound()` for a
 * missing, expired OR revoked token. Spec §4: the three cases are
 * indistinguishable BY DESIGN (a revoked-link probe must read identically to
 * a token that never existed), so this copy names none of them specifically.
 */

import { Logo } from "@tracelanedev/ui";
import Link from "next/link";

export default function SharedTraceNotFound() {
	return (
		<div className="flex min-h-screen flex-col">
			<header className="flex items-center border-b border-line px-6 py-4">
				<Logo withWordmark height={22} />
			</header>
			<div className="flex flex-1 items-center justify-center p-6">
				<div className="mx-auto max-w-md py-16 text-center">
					<p className="font-mono text-5xl font-semibold leading-none text-ink-3">
						404
					</p>
					<h1 className="t-h1 mt-3">Shared trace unavailable</h1>
					{/* Exact copy, spec §4. */}
					<p className="mt-1.5 text-sm text-ink-2">
						This shared trace has expired or was revoked. Ask the owner for a
						new link.
					</p>
					<div className="mt-6">
						<Link
							href="https://tracelane.dev"
							className="inline-flex h-9 items-center rounded-lg border border-line bg-surface px-4 text-sm font-medium text-ink transition-colors hover:bg-surface-2"
						>
							Recorded with Tracelane — record your own →
						</Link>
					</div>
				</div>
			</div>
		</div>
	);
}
