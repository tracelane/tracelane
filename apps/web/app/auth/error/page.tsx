import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Sign-in didn't complete" };

/**
 * Where `/auth/callback` sends a failed sign-in (B-561, 2026-09-27) — a page a person can
 * act on, often on a phone, instead of a JSON body. No auto-redirect back to `/sign-in`:
 * a persistent provider error would otherwise loop. The error detail stays in the
 * server log (`[auth/callback]`), never on this page.
 */
export default function SignInErrorPage() {
	return (
		<div className="min-h-screen grid place-items-center bg-bg p-6">
			<div className="max-w-md space-y-4 text-left">
				<h1 className="t-h1">Sign-in didn&apos;t complete</h1>
				<p className="text-sm text-ink-2">
					Something interrupted the sign-in. Nothing is wrong with your
					workspace — please try again.
				</p>
				<Link
					href="/sign-in"
					className="inline-block rounded-control bg-action px-4 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90"
				>
					Sign in again
				</Link>
			</div>
		</div>
	);
}
