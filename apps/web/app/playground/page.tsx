/**
 * Playground [V1.1] — prototype prompts against connected providers, with every
 * run captured as a trace. Empty-state only at V1.
 */

import { ComingSoon } from "@/components/empty-states/ComingSoon";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Playground — Tracelane" };

export default function PlaygroundPage() {
	return (
		<ComingSoon
			title="Playground"
			description="Prototype prompts against your connected providers through the gateway — every run is captured as a trace, so experimentation and observability share one record."
		/>
	);
}
