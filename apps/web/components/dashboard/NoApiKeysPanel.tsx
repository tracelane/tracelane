"use client";

/**
 * "You have no active API keys" — the dashboard panel that replaced a redirect.
 *
 * R201. `/` used to send any tenant with zero non-revoked keys to the 3-step
 * onboarding wizard. That conflated "new signup" with "has no key right now",
 * and the second is an ordinary state: revoke your last old key and you were
 * demoted to a new user. On 2026-08-26 that was 15 of 19 production tenants,
 * including the only Team-plan account.
 *
 * WHAT THIS KEEPS. The redirect existed to stop a genuinely new user landing on
 * an empty dashboard with no idea what to do next. That concern is real and is
 * why the check moved here instead of being deleted: the same information and
 * the same call to action, on the surface where the emptiness is actually
 * visible, offered rather than imposed. A new user still gets pointed at the
 * next step; an existing one gets their product.
 *
 * IT DISAPPEARS ON ITS OWN. The server only renders this when the active-key
 * count is zero, so minting a key removes it without anything being dismissed,
 * cleared or migrated. Dismissal is a convenience for someone who does not want
 * a key yet — deliberately NOT a database column, because a per-browser
 * preference does not belong in the control plane and a column would need a
 * migration ordered ahead of a gateway deploy for a banner.
 *
 * `localStorage` is read in an effect, not in `useState`'s initializer: the
 * initializer also runs during SSR where `window` does not exist, and reading
 * it there would either throw or render the panel and then rip it away. `null`
 * means "not yet known" and renders nothing, so the panel never flashes for
 * someone who already dismissed it. Every access is wrapped — Safari private
 * mode and "block site data" both make the accessor itself throw, and a banner
 * must never be able to break the dashboard.
 */

import { Button } from "@tracelanedev/ui";
import Link from "next/link";
import { useEffect, useState } from "react";

export interface NoApiKeysPanelProps {
	/** Internal workspace UUID — scopes dismissal so a second workspace still shows it. */
	workspaceId: string;
}

export function NoApiKeysPanel({ workspaceId }: NoApiKeysPanelProps) {
	const storageKey = `tl.dismissed.no-api-keys.${workspaceId}`;
	// null = not yet read. Renders nothing, so a dismissed panel never flashes.
	const [dismissed, setDismissed] = useState<boolean | null>(null);

	useEffect(() => {
		try {
			setDismissed(window.localStorage.getItem(storageKey) === "1");
		} catch {
			// Storage unavailable (private mode, blocked site data). Show the
			// panel — the fail-open direction for a hint is to be visible.
			setDismissed(false);
		}
	}, [storageKey]);

	if (dismissed !== false) return null;

	return (
		<section
			aria-labelledby="no-api-keys-heading"
			className="surface-card flex flex-col gap-4 rounded-[var(--radius-card)] border border-line p-5 sm:flex-row sm:items-center sm:justify-between"
		>
			<div className="min-w-0">
				<h2 id="no-api-keys-heading" className="text-sm font-semibold text-ink">
					No active API keys
				</h2>
				<p className="mt-1 text-sm text-ink-2">
					Your workspace has no key the gateway will accept, so nothing can send
					traffic to it yet. Create one to start capturing traces.
				</p>
			</div>
			<div className="flex flex-none items-center gap-2">
				<Button
					variant="ghost"
					size="sm"
					type="button"
					onClick={() => {
						setDismissed(true);
						try {
							window.localStorage.setItem(storageKey, "1");
						} catch {
							// Dismissal does not survive the reload. Better than throwing.
						}
					}}
				>
					Dismiss
				</Button>
				{/* A REAL ANCHOR, not a Button with a router.push. `Button` renders a
				    bare <button> and does not forward to a child, and the primary
				    variant's classes are not exported — so they are written out here.
				    Routing a call to action through onClick would cost middle-click,
				    cmd-click and "copy link address" on the one control this panel
				    exists to offer. The class list mirrors Button's base + primary +
				    size-sm exactly; if that primitive gains `asChild`, collapse this. */}
				<Link
					href="/settings/api-keys"
					className="inline-flex h-8 items-center justify-center gap-2 whitespace-nowrap rounded-md bg-selected px-3 text-xs font-medium text-selected-on transition-[color,background-color,border-color,opacity,scale] hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring active:scale-[0.98] active:opacity-80"
				>
					Create an API key
				</Link>
			</div>
		</section>
	);
}
