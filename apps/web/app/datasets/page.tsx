/**
 * Datasets [V1.1] — curated, labeled trace sets to replay against prompt/model
 * changes. Empty-state only at V1 (see components/empty-states/ComingSoon).
 */

import { ComingSoon } from "@/components/empty-states/ComingSoon";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Datasets — Tracelane" };

export default function DatasetsPage() {
	return (
		<ComingSoon
			title="Datasets"
			description="Curate labeled sets of real traces, then replay them against a prompt or model change to catch regressions before they reach production."
		/>
	);
}
