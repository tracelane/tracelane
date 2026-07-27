/**
 * /support — the in-product support page. Replaces the old right-hand slide-out
 * (founder: "make it a proper page"). Renders the shared <SupportForm> inside the
 * app frame; the nav "Support" item links here instead of opening an overlay.
 */

import { SupportForm } from "@/components/support/SupportForm";
import { Card } from "@tracelanedev/ui";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Support — Tracelane" };

export default function SupportPage() {
	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mx-auto max-w-2xl space-y-5">
				<header>
					<h1 className="text-2xl font-semibold tracking-tight text-ink">
						Support
					</h1>
					<p className="mt-1 text-sm text-ink-2">
						Ask a question, share feedback, or report a bug. We follow up by
						email — include as much detail as you can.
					</p>
				</header>
				<Card className="p-5">
					<SupportForm />
				</Card>
			</div>
		</div>
	);
}
