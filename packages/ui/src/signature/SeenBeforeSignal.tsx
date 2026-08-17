import { cn } from "../lib/cn";

export interface SeenBeforeSignalProps {
	/**
	 * Per-tenant "your hits" count. NEVER a network count the registry can't
	 * substantiate.
	 *
	 * OPTIONAL by design (OBS-33): until the per-tenant aggregate has loaded there is
	 * no honest number to show, so the badge renders the signature WITHOUT a count
	 * rather than substituting one that happens to be in hand. An invented number on
	 * a trust surface is worse than an absent one.
	 */
	count?: number;
	/** e.g. "Tool-definition drift — matches a known signature". */
	signatureLabel: string;
	/** → View signature. */
	href?: string;
	/**
	 * Optional native browser tooltip (HTML `title` attr) shown on hover.
	 * Used to surface the full AFT-1 id + human label without expanding the
	 * inline badge, e.g. "AFT-TOOL-SCHEMA-001: Hallucinated tool-call schema violation".
	 */
	title?: string;
	className?: string;
}

/**
 * The "seen-before" ambient signal — when a span matches a known failure
 * signature it glows amber inline (the spellcheck-underline pattern), NOT a
 * separate tab. Felt where the failure is (the design-system spec §3.3). Amber is a
 * status cue, deliberately distinct from the action and the provenance seal.
 */
export function SeenBeforeSignal({
	count,
	signatureLabel,
	href,
	title,
	className,
}: SeenBeforeSignalProps) {
	return (
		<span
			title={title}
			className={cn(
				"inline-flex items-center gap-1.5 rounded-md bg-warn-soft px-1.5 py-0.5 text-[11px] text-warn-ink underline decoration-warn decoration-wavy underline-offset-2",
				className,
			)}
		>
			<span aria-hidden>◆</span>
			{typeof count === "number" && (
				<span className="font-semibold tabular-nums">SEEN {count}×</span>
			)}
			<span className="text-ink-2">— {signatureLabel}</span>
			{href && (
				<a href={href} className="text-action-ink no-underline hover:underline">
					View signature →
				</a>
			)}
		</span>
	);
}
