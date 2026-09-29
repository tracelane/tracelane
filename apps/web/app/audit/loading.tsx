import { AuditWorkflow } from "@/components/audit/AuditWorkflow";
export default function Loading() {
	return (
		<div aria-live="polite" aria-label="Loading audit evidence">
			<p className="mb-4 text-sm text-ink-2">
				Loading evidence. No integrity verdict yet.
			</p>
			<AuditWorkflow report={null} rows={0} batches={0} loading />
		</div>
	);
}
