import { cn } from "../lib/cn";

export interface HashChainThreadProps {
	/**
	 * HashChainThread — a fixed-height dotted `--seal` connector for the trace spine.
	 * One of the three signature visualisations `index.ts` calls "the purple cow".
	 *
	 * ── ⚠ NEVER HAD A CALLER, AND CANNOT GET ONE AS WRITTEN ─────────────────────
	 * Documented 2026-08-22. Built `101aae7e` (2026-06-15) from
	 * `:83-85` §3.2 (`:10065`).
	 * `git log -S'<HashChainThread'` returns exactly ONE commit — `45b0f4cb` — and that
	 * commit adds only a JSON document *recording its absence*. No JSX call site has
	 * ever existed. `TranscriptSpine` drew the same rail inline from day one and owns
	 * it today at `:151`.
	 *
	 * IT IS UN-SHIPPABLE BY RULING, NOT BY OVERSIGHT — two, both still binding:
	 *
	 * 1. `ad4af0ed` (2026-07-13), "Founder rulings on the four deferred polish items" ②.
	 *    The spine used to be `--seal` unconditionally, *"implying per-trace chain
	 *    verification even on unverified traces"*. It is now green ONLY on a real
	 *    verdict — `verified === true ? "border-seal" : "border-line-2"` — and the
	 *    ruling states *"TraceDetailView supplies no verdict … so its rail is neutral."*
	 *    **`HashChainThreadProps` takes only `height` and `className`. NO DATA INPUT.**
	 *    It is structurally incapable of obeying that ruling: it can only ever paint
	 *    unconditional green, which is precisely the defect the ruling removed.
	 *
	 * 2. **** (`:620`), RESOLVED 2026-06-28, founder-approved: the hash
	 *    chain is **per-TENANT** (`audit_log`), not per-trace, and there is no per-trace
	 *    verify path — so the trace view OMITS the provenance mark rather than fabricate
	 *    integrity. A thread drawn between spans would assert a cryptographic link the
	 *    data does not contain.
	 *
	 * BOTH HALVES OF THE §3.2 SPEC DID SHIP, elsewhere and honestly: the gated spine
	 * rail (`TranscriptSpine.tsx:143-152`), the explicit `seq · hash ← prev` chain
	 * (`apps/web/components/audit/AuditLedgerView.tsx:1605-1618`), and the per-trace
	 * `ChainStatusChip` (`15c66e72`, live at `apps/web/app/traces/[traceId]/page.tsx`).
	 *
	 * TO SHIP IT, IN ORDER: (1) a per-trace chain verdict must EXIST — data fact
	 * must change; (2) this component must take that verdict as a prop and go neutral
	 * without it. Neither is true today.
	 *
	 * A NOTE ON THE REPO'S OWN BOOKKEEPING, since it is wrong here: `:9651`
	 * triages this as "cosmetic" because *"its file is live via ProvenanceChip"*. The
	 * FILE is imported; the named export is not — and `ProvenanceChip` is itself dark at
	 * runtime, gated on `verified !== undefined`, which `TraceDetailView` never supplies.
	 * The RULINGS above are genuine. That triage line is not.
	 */
	height?: number;
	className?: string;
}

/**
 * The hash-chain thread — a thin dotted vertical connector in `--seal`, representing
 * the tamper-evident chain and rendered down the trace spine. The single most
 * distinctive provenance visual (no competitor renders provenance). Pair with
 * <ProvenanceChip />. Copy rule (ADR-021/023): "tamper-evident", never "tamper-proof".
 *
 * `--seal` WAS A TEAL and this comment said so; since 2026-08-22 it is the SAME green as
 * `--ok`, deliberately — under the P0 brief green means one thing, healthy/verified, and
 * a second green would be a second meaning nobody can name (tokens.css says this at the
 * value). The token name is what is load-bearing here, never the hue behind it.
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

/** The "Verified · chain ✓" provenance chip — the rationed `--seal` mark, and the ONLY
 *  place a trace may wear provenance green. An unverified chain falls back to `--warn`,
 *  never to a neutral, so "we did not check" never renders as "we checked and it is
 *  fine". */
export function ProvenanceChip({ verified, className }: ProvenanceChipProps) {
	return (
		<span
			className={cn(
				"inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-2xs font-semibold",
				verified ? "bg-seal-soft text-seal-ink" : "bg-warn-soft text-warn-ink",
				className,
			)}
		>
			{verified ? "Verified · chain ✓" : "Chain unverified"}
		</span>
	);
}
