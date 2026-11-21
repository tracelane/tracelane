"use client";

/**
 * The three questions an auditor asks, answered first (AUD-40 Part C). The state words
 * come from `summarizeAudit`, which never says "yes" without a report.
 */
import type { Answer, AuditSummary } from "@/app/audit/answer";
import { cn } from "@tracelanedev/ui";

const LABEL: Record<Answer["state"], string> = {
	yes: "Yes",
	partly: "Partly",
	no: "No",
	unknown: "Not established",
};
const TONE: Record<Answer["state"], string> = {
	yes: "text-seal-ink",
	partly: "text-ink",
	no: "text-danger-ink",
	unknown: "text-ink-3",
};

export function AuditAnswers({ summary }: { summary: AuditSummary }) {
	const rows: Array<[string, Answer]> = [
		["Unchanged?", summary.unaltered],
		["Signed and anchored?", summary.vouched],
		["How much was checked?", summary.coverage],
	];
	return (
		<dl
			aria-label="Audit answers"
			className="mt-5 grid gap-px overflow-hidden border border-line bg-line sm:grid-cols-3"
		>
			{rows.map(([q, a]) => (
				<div key={q} className="bg-surface p-4" data-answer={a.state}>
					<dt className="text-xs text-ink-3">{q}</dt>
					<dd className={cn("mt-1 text-sm font-semibold", TONE[a.state])}>
						{LABEL[a.state]}
					</dd>
					<dd className="mt-1 text-xs leading-relaxed text-ink-2">{a.text}</dd>
				</div>
			))}
		</dl>
	);
}
