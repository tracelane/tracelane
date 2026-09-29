"use client";
import type { ArmAggregate } from "@/app/api/experiments/route";
import Link from "next/link";
import { useId, useState } from "react";
export function RunComparisonPicker({
	experimentId,
	arms,
}: { experimentId: string; arms: ArmAggregate[] }) {
	const id = useId();
	const finished = arms.filter(
		(a) => a.eval_run_id && ["passed", "failed", "errored"].includes(a.status),
	);
	const [baseline, setBaseline] = useState(finished[0]?.arm_id ?? "");
	const [candidate, setCandidate] = useState(finished[1]?.arm_id ?? "");
	if (finished.length < 2)
		return <p>Comparing unlocks when two runs finish.</p>;
	const valid =
		baseline !== candidate &&
		finished.some((a) => a.arm_id === baseline) &&
		finished.some((a) => a.arm_id === candidate);
	return (
		<div className="space-y-3">
			<p className="text-sm text-ink-2">
				Compare finished runs from this experiment's shared dataset snapshot.
				Better and worse describe score or pass/fail changes; cost and latency
				changes are shown separately.
			</p>
			<label className="block" htmlFor={`${id}-baseline`}>
				Baseline run
			</label>
			<select
				id={`${id}-baseline`}
				className="max-w-full border border-line bg-surface p-2"
				value={baseline}
				onChange={(e) => setBaseline(e.target.value)}
			>
				{finished.map((a) => (
					<option key={a.arm_id} value={a.arm_id}>
						{a.arm_label || a.model} · {a.eval_run_id}
					</option>
				))}
			</select>
			<label className="block" htmlFor={`${id}-candidate`}>
				Candidate run
			</label>
			<select
				id={`${id}-candidate`}
				className="max-w-full border border-line bg-surface p-2"
				value={candidate}
				onChange={(e) => setCandidate(e.target.value)}
			>
				{finished.map((a) => (
					<option key={a.arm_id} value={a.arm_id}>
						{a.arm_label || a.model} · {a.eval_run_id}
					</option>
				))}
			</select>
			{valid ? (
				<Link
					className="block underline"
					href={`/experiments/${encodeURIComponent(experimentId)}/compare?a=${encodeURIComponent(baseline)}&b=${encodeURIComponent(candidate)}`}
				>
					Compare runs
				</Link>
			) : (
				<p>Choose two different runs.</p>
			)}
		</div>
	);
}
