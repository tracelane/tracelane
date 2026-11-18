import Link from "next/link";

export interface InvestigationFocusProps {
	windowLabel: string;
	modelErrorCount: number;
	requestCount: number;
	modelErrorDataAvailable: boolean;
	modelErrorsHref: string;
	signatureDataAvailable: boolean;
	topSignature?: {
		id: string;
		hits: number;
		href: string;
	};
}

export function InvestigationFocus({
	windowLabel,
	modelErrorCount,
	requestCount,
	modelErrorDataAvailable,
	modelErrorsHref,
	signatureDataAvailable,
	topSignature,
}: InvestigationFocusProps) {
	const hasFailureSignal =
		(modelErrorDataAvailable && modelErrorCount > 0) ||
		(signatureDataAvailable && !!topSignature);
	return (
		<section
			aria-labelledby="investigation-focus-heading"
			className="surface-card space-y-3 border border-line p-4 sm:p-5"
		>
			<div className="flex flex-wrap items-start justify-between gap-2">
				<div>
					<h2
						id="investigation-focus-heading"
						className="text-sm font-semibold text-ink"
					>
						{hasFailureSignal
							? "Investigate recorded signals"
							: "Where to look next"}
					</h2>
					<p className="mt-1 text-xs text-ink-2">
						{windowLabel}. Only signals present in your workspace are shown; an
						HTTP success alone does not prove an agent task succeeded.
					</p>
				</div>
				<Link
					href="/traces"
					className="text-xs font-medium text-action-ink underline underline-offset-4"
				>
					All traces
				</Link>
			</div>
			<div className="grid gap-2 md:grid-cols-2">
				{modelErrorDataAvailable ? (
					<Link
						href={modelErrorsHref}
						className="rounded-control border border-line bg-surface px-3 py-3 transition-colors hover:bg-surface-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<span className="block text-xs font-semibold text-ink">
							Failed model calls
						</span>
						<span className="mt-1 block text-sm font-mono tabular-nums text-ink">
							{requestCount === 0
								? "No model calls recorded in this window."
								: `${modelErrorCount.toLocaleString("en-US")} recorded`}
						</span>
						<span className="mt-1 block text-xs text-ink-2">
							{requestCount > 0 &&
								(modelErrorCount > 0
									? "View traces with errors →"
									: "No model-call errors recorded in this window; task outcomes may still fail.")}
						</span>
					</Link>
				) : (
					<div className="rounded-control border border-line bg-surface px-3 py-3">
						<span className="block text-xs font-semibold text-ink">
							Failed model calls
						</span>
						<span className="mt-1 block text-sm text-ink-2">
							Unavailable — gateway read not confirmed.
						</span>
					</div>
				)}
				{signatureDataAvailable && topSignature ? (
					<Link
						href={topSignature.href}
						className="rounded-control border border-line bg-surface px-3 py-3 transition-colors hover:bg-surface-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<span className="block text-xs font-semibold text-ink">
							Most frequent matching signature
						</span>
						<span className="mt-1 block break-all text-sm font-mono text-ink">
							{topSignature.id}
						</span>
						<span className="mt-1 block text-xs text-ink-2">
							{topSignature.hits.toLocaleString("en-US")} matches · Investigate
							linked traces →
						</span>
					</Link>
				) : (
					<div className="rounded-control border border-line bg-surface px-3 py-3">
						<span className="block text-xs font-semibold text-ink">
							Failure signatures
						</span>
						<span className="mt-1 block text-sm text-ink-2">
							{signatureDataAvailable
								? "No matching failure signatures recorded in the selected window."
								: "Unavailable — signature read not confirmed."}
						</span>
					</div>
				)}
			</div>
		</section>
	);
}
