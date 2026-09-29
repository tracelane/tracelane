"use client";
import type { IdentityKind } from "@/lib/kya/identity";
import type { ActivityLoad, KyaWindow } from "@/lib/kya/types";
import { useEffect, useState } from "react";
import { ActivityView } from "./ActivityView";
export function AgentsClient({
	kind,
	window,
	profileKey,
}: { kind: IdentityKind; window: KyaWindow; profileKey?: string }) {
	const [result, setResult] = useState<ActivityLoad>({ status: "loading" });
	const [attempt, setAttempt] = useState(0);
	// Retry explicitly starts another read of the same URL.
	// biome-ignore lint/correctness/useExhaustiveDependencies: attempt is the retry trigger.
	useEffect(() => {
		const controller = new AbortController();
		setResult({ status: "loading" });
		const path = profileKey
			? `/api/kya/identities/${kind}/${encodeURIComponent(profileKey)}`
			: "/api/kya/identities";
		fetch(`${path}?kind=${kind}&window=${window}`, {
			signal: controller.signal,
			cache: "no-store",
		})
			.then(async (response) =>
				response.ok
					? { status: "ready" as const, data: await response.json() }
					: { status: "error" as const, code: response.status },
			)
			.then((value) => {
				if (!controller.signal.aborted) setResult(value);
			})
			.catch(() => {
				if (!controller.signal.aborted) setResult({ status: "error", code: 0 });
			});
		return () => controller.abort();
	}, [kind, window, profileKey, attempt]);
	return (
		<ActivityView
			kind={kind}
			window={window}
			profileKey={profileKey}
			result={result}
			onRetry={() => setAttempt((value) => value + 1)}
		/>
	);
}
