import { AgentsClient } from "@/components/kya/AgentsClient";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
export const metadata: Metadata = { title: "Identity activity — Tracelane" };
export default async function ProfilePage({
	params,
	searchParams,
}: {
	params: Promise<{ kind: string; key: string }>;
	searchParams: Promise<{ window?: string }>;
}) {
	const [{ kind, key }, q] = await Promise.all([params, searchParams]);
	if (kind !== "agent" && kind !== "model") notFound();
	return (
		<AgentsClient
			key={`${kind}:${key}:${q.window}`}
			kind={kind}
			profileKey={key}
			window={q.window === "30d" ? "30d" : "7d"}
		/>
	);
}
