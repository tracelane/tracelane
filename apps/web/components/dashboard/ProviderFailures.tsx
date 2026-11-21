import { GatewayError } from "@/lib/gateway";
import {
	type ProviderFailuresData,
	fetchProviderFailuresFor,
} from "@/lib/metrics/fetch";
import { fmtCount } from "@/lib/metrics/format";
import type { TimeRange } from "@/lib/metrics/time-range";
import { Card } from "@tracelanedev/ui";

export async function ProviderFailures({ range }: { range: TimeRange }) {
	let data: ProviderFailuresData | null;
	try {
		data = await fetchProviderFailuresFor(range);
	} catch (error) {
		if (!(error instanceof GatewayError) || error.status !== 403) throw error;
		return (
			<section aria-label="Recorded provider failures">
				<Card className="p-5">
					<h2 className="t-card-title">Recorded provider failures</h2>
					<p className="mt-2 text-xs text-ink-2">
						Access denied. Ask a workspace administrator for access to these
						metrics.
					</p>
				</Card>
			</section>
		);
	}
	return (
		<section aria-label="Recorded provider failures">
			<Card className="p-5">
				<h2 className="t-card-title">Recorded provider failures</h2>
				<p className="mt-1 text-xs text-ink-3">{range.label}</p>
				{data === null ? (
					<p className="mt-3 text-xs text-ink-2">
						Recorded failure data unavailable. The gateway may not support this
						read yet.
					</p>
				) : (
					<>
						<p className="mt-3 text-sm text-ink">
							{fmtCount(data.totals.failed)} recorded failed attempts
						</p>
						<p className="mt-1 text-xs text-ink-3">
							Attempt records on {fmtCount(data.totals.recorded_spans)} of{" "}
							{fmtCount(data.totals.captured_spans)} captured provider spans.{" "}
							{fmtCount(data.totals.capped_spans)}{" "}
							{data.totals.capped_spans === 1 ? "span" : "spans"} reached the{" "}
							{fmtCount(data.record_cap)}-record cap. Recording varies by route;
							these counts do not cover all provider calls.
						</p>
						<details className="mt-2 text-xs text-ink-3">
							<summary className="cursor-pointer text-ink-2">
								What these counts cover
							</summary>
							<p className="mt-2">
								Clean single attempts are intentionally omitted. Missing or
								older writers and capped records can leave attempts unrecorded.
								These counts describe stored failure records, not all provider
								calls. Unknown means the failed attempt has no usable HTTP
								failure status, including locally generated deadlines. Skipped
								candidates and successful attempts are excluded.
							</p>
						</details>
						{data.providers.length === 0 ? (
							<p className="mt-4 text-xs text-ink-2">
								No recorded failed attempts in this window. This does not
								establish that every provider call succeeded.
							</p>
						) : (
							<div className="mt-4 overflow-x-auto">
								<table className="w-full text-left text-xs">
									<thead className="border-b border-line text-ink-3">
										<tr>
											{[
												"Provider",
												"Failed",
												"429",
												"5xx",
												"Other",
												"Unknown",
											].map((label) => (
												<th key={label} className="px-2 py-2 font-medium">
													{label}
												</th>
											))}
										</tr>
									</thead>
									<tbody>
										{data.providers.map((row) => (
											<tr key={row.provider} className="border-b border-line">
												<td className="max-w-40 break-words px-2 py-2 text-ink">
													{row.provider || "Unreported provider"}
												</td>
												{[
													row.failed,
													row.rate_limited,
													row.server_error,
													row.other,
													row.unknown,
												].map((value, index) => (
													<td
														key={
															["failed", "429", "5xx", "other", "unknown"][
																index
															]
														}
														className="px-2 py-2 font-mono tabular-nums text-ink"
													>
														{fmtCount(value)}
													</td>
												))}
											</tr>
										))}
									</tbody>
								</table>
							</div>
						)}
						{data.truncated && (
							<p className="mt-2 text-xs text-ink-3">
								Top provider rows shown; totals cover all recorded provider
								groups.
							</p>
						)}
					</>
				)}
			</Card>
		</section>
	);
}
