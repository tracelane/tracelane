import { AgentsClient } from "@/components/kya/AgentsClient";
import type { Metadata } from "next";
export const metadata: Metadata = { title: "Agents — Tracelane" };
export default async function AgentsPage({
	searchParams,
}: { searchParams: Promise<{ kind?: string; window?: string }> }) {
	const q = await searchParams;
	return (
		<AgentsClient
			key={`${q.kind}:${q.window}`}
			kind={q.kind === "model" ? "model" : "agent"}
			window={q.window === "30d" ? "30d" : "7d"}
		/>
	);
}
