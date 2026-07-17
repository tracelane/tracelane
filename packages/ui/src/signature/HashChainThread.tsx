import { cn } from "../lib/cn";

export interface HashChainThreadProps {
	/** Height of the connector segment (px). Renders down the trace spine. */
	height?: number;
	className?: string;
}

/**
 * The hash-chain thread — a thin teal dotted vertical connector representing the
 * tamper-evident chain, rendered down the trace spine. The single most
 * distinctive provenance visual (no competitor renders provenance). Pair with
 * <ProvenanceChip />. Copy rule (ADR-021/023): "tamper-evident", never "tamper-proof".
 */
export function HashChainThread({
	height = 24,
	className,
}: HashChainThreadProps) {
	return (
		<span
			aria-hidden
			style={{ height }}
			className={cn(
				"inline-block w-px border-l border-dashed border-seal",
				className,
			)}
		/>
	);
}

export interface ProvenanceChipProps {
	/** Chain verification result (from `tlane verify` / the chain replay). */
	verified: boolean;
	className?: string;
}

/** The "Verified · chain ✓" provenance chip (teal). The rationed teal seal. */
export function ProvenanceChip({ verified, className }: ProvenanceChipProps) {
	return (
		<span
			className={cn(
				"inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold",
				verified ? "bg-seal-soft text-seal-ink" : "bg-warn-soft text-warn",
				className,
			)}
		>
			{verified ? "Verified · chain ✓" : "Chain unverified"}
		</span>
	);
}
