"use client";
import {
	RefusalNote,
	useCan,
	useControlWrite,
} from "@/components/gateway/control";
import { Button } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { useState } from "react";

/** Approve / Deny, bound to the digest of the descriptor the page rendered. */
export function DecisionPanel({
	approvalId,
	digest,
}: { approvalId: string; digest: string }) {
	const { allowed, reason } = useCan("approve_tool_calls");
	const router = useRouter();
	const [note, setNote] = useState("");
	const done = () => router.refresh();
	const yes = useControlWrite("POST", `approvals/${approvalId}/approve`, []);
	const no = useControlWrite("POST", `approvals/${approvalId}/deny`, []);
	if (!allowed) return <p className="text-sm text-ink-2">{reason}</p>;
	const body = () => ({
		...(note.trim() ? { note: note.trim() } : {}),
		descriptor_digest: digest,
	});
	const send = (m: typeof yes) =>
		m.mutate(body(), {
			onSuccess: done,
			// A changed request means the panel on screen is stale: reload it.
			onError: (e) =>
				(e.refusal.code === "descriptor_mismatch" ||
					e.refusal.code === "approval_expired") &&
				done(),
		});
	const busy = yes.isPending || no.isPending;
	return (
		<div className="space-y-2">
			<label className="block text-sm">
				Note
				<input
					className="mt-1 w-full rounded-control border border-line px-3 py-2 text-sm"
					maxLength={500}
					value={note}
					onChange={(e) => setNote(e.target.value)}
				/>
			</label>
			<div className="flex gap-2">
				<Button disabled={busy} onClick={() => send(yes)}>
					Approve
				</Button>
				<Button variant="secondary" disabled={busy} onClick={() => send(no)}>
					Deny
				</Button>
			</div>
			<RefusalNote error={yes.error ?? no.error} />
		</div>
	);
}
