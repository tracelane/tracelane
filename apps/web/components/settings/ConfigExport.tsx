"use client";
import { Button } from "@tracelanedev/ui";

/**
 * ConfigExport — the "Download configuration" control on the gateway settings page.
 * One click fetches the workspace's configuration document through the dashboard relay
 * and saves it as `tracelane-config-<UTC date>.json`. The gateway owns the role check:
 * a 403 is worded here, never guessed from the session.
 */

import { useState } from "react";

const ENDPOINT = "/api/settings/config-export";

/** UTC calendar date, `YYYY-MM-DD` — never the viewer's zone. */
export function exportFileName(now: Date): string {
	return `tracelane-config-${now.toISOString().slice(0, 10)}.json`;
}

type State =
	| { kind: "idle" }
	| { kind: "busy" }
	| { kind: "forbidden" }
	| { kind: "failed" };

export function ConfigExport() {
	const [state, setState] = useState<State>({ kind: "idle" });

	async function download() {
		setState({ kind: "busy" });
		try {
			const res = await fetch(ENDPOINT, { cache: "no-store" });
			if (res.status === 403) {
				setState({ kind: "forbidden" });
				return;
			}
			if (!res.ok) {
				setState({ kind: "failed" });
				return;
			}
			const blob = new Blob([await res.text()], { type: "application/json" });
			const url = URL.createObjectURL(blob);
			const link = document.createElement("a");
			link.href = url;
			link.download = exportFileName(new Date());
			document.body.appendChild(link);
			link.click();
			link.remove();
			URL.revokeObjectURL(url);
			setState({ kind: "idle" });
		} catch {
			setState({ kind: "failed" });
		}
	}

	return (
		<div className="space-y-2">
			<Button
				type="button"
				disabled={state.kind === "busy"}
				onClick={() => void download()}
			>
				{state.kind === "busy" ? "Preparing…" : "Download configuration"}
			</Button>
			{state.kind === "forbidden" && (
				<p className="text-sm text-ink-2" role="alert">
					Only workspace admins can export configuration.
				</p>
			)}
			{state.kind === "failed" && (
				<p className="text-sm text-ink-2" role="alert">
					The configuration could not be exported.{" "}
					<Button
						variant="bare"
						type="button"
						className="underline"
						onClick={() => void download()}
					>
						Retry
					</Button>
				</p>
			)}
		</div>
	);
}
