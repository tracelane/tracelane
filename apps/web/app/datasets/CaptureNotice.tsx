import Link from "next/link";
export function CaptureNotice() {
	return (
		<div className="space-y-2 rounded-control border border-line bg-surface-2 p-3 text-sm text-ink-2">
			<p className="font-medium text-ink">
				This workspace does not record prompt content.
			</p>
			<p>
				Dataset cases need recorded input. Enable input capture in{" "}
				<Link className="underline" href="/settings/workspace">
					Settings → Workspace
				</Link>
				, then record a new trace. Existing traces will not gain content.
			</p>
		</div>
	);
}
