"use client";
import { apiFetch } from "@/lib/api-fetch";
import { useEffect, useState } from "react";

/** Unknown settings never imply that recording is off. The write route remains authoritative. */
export function useInputCapture(enabled: boolean) {
	const [input, setInput] = useState<boolean | null>(null);
	useEffect(() => {
		if (!enabled) return;
		let active = true;
		void apiFetch<{ effective?: { input?: unknown } }>(
			"/api/settings/content-capture",
			{ cache: "no-store" },
		)
			.then((data) => {
				if (active)
					setInput(
						typeof data?.effective?.input === "boolean"
							? data.effective.input
							: null,
					);
			})
			.catch(() => {
				if (active) setInput(null);
			});
		return () => {
			active = false;
		};
	}, [enabled]);
	return enabled ? input : null;
}
