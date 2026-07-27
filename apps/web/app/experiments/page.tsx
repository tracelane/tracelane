/**
 * Experiments [V1.1] — A/B evaluations across prompts, models, and guardrail
 * configs, scored against a dataset. Empty-state only at V1.
 */

import { ComingSoon } from "@/components/empty-states/ComingSoon";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Experiments — Tracelane" };

export default function ExperimentsPage() {
	return (
		<ComingSoon
			title="Experiments"
			description="Run side-by-side evaluations across prompts, models, and guardrail configs — scored against a dataset — so a change ships only when it measurably wins."
		/>
	);
}
