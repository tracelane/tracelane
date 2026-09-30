import type { GenerationDetails } from "@/lib/generation-issues";
import { MODEL_DATE_SUFFIX, normalizeModel } from "@/lib/kya/identity";
import { IssueChip } from "./IssueChip";

/** Authenticated evidence only; older and public-share shapes carry neither field. */
export function GenerationEvidence({
	evidence,
	attributes,
}: { evidence: GenerationDetails; attributes: Record<string, unknown> }) {
	if (evidence.issues === undefined && evidence.signals_recorded === undefined)
		return null;
	const text = (key: string) =>
		typeof attributes?.[key] === "string"
			? (attributes[key] as string).trim()
			: "";
	const requested = text("gen_ai_request_model");
	const reported = text("gen_ai_response_model");
	const verdict = text("tracelane_model_substitution");
	const snapshot =
		verdict === "provider" &&
		requested &&
		reported &&
		requested !== reported &&
		MODEL_DATE_SUFFIX.test(reported) &&
		normalizeModel(requested) === normalizeModel(reported);
	const signals = evidence.signals_recorded;
	return (
		<section
			aria-label="Generation issues"
			className="space-y-2 rounded-card border border-line bg-surface-2 p-3"
		>
			<h3 className="text-sm font-semibold text-ink">Generation issues</h3>
			{evidence.issues?.length ? (
				<ul className="space-y-2">
					{evidence.issues.map((issue) => (
						<li key={issue.kind}>
							<IssueChip issue={issue} />
							<p className="mt-1 break-words text-xs text-ink-2">
								{issue.detail}
							</p>
						</li>
					))}
				</ul>
			) : (
				<p className="text-xs text-ink-2">
					No issues flagged from the recorded signals.
				</p>
			)}
			{(requested || reported) && (
				<p className="break-words text-xs text-ink-2">
					Requested: <code>{requested || "not recorded"}</code> → provider
					reported: <code>{reported || "not recorded"}</code>
				</p>
			)}
			{snapshot && (
				<p className="text-xs text-ink-3">
					Resolved to snapshot <code>{reported}</code>
				</p>
			)}
			<h4 className="text-xs font-semibold text-ink">Signals recorded</h4>
			{!signals ? (
				<p className="text-xs text-ink-2">
					Signal availability was not returned by the gateway.
				</p>
			) : (
				<div className="space-y-1 break-words text-xs text-ink-2">
					{!signals.attributes_readable && (
						<p>Recorded attributes could not be read.</p>
					)}
					<p>
						Recorded:{" "}
						{signals.present.length
							? signals.present.join(", ")
							: "none of the generation fields"}
					</p>
					{signals.missing.length > 0 && (
						<p>Not recorded: {signals.missing.join(", ")}</p>
					)}
					{!signals.chat_operation && (
						<p>
							No chat or messages operation recorded; chat-only issues cannot be
							assessed.
						</p>
					)}
				</div>
			)}
		</section>
	);
}
