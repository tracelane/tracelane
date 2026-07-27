"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

const POLL_MS = 2500;
const SLOW_AFTER_S = 60;

type State = "waiting" | "found" | "error";
type ErrKind = "gateway" | "auth";

/**
 * Verify-by-real-trace — the onboarding "magic moment" (O.5/O.6).
 *
 * Polls for the tenant's first trace and DISTINGUISHES "no trace yet" from
 * "something's wrong" — never an eternal optimistic spinner (the #1 silent
 * activation killer). 200+empty → keep waiting; 502/4xx → a real error state
 * with guidance; nothing after 60s → a "check X" fallback. On arrival it
 * deep-links into the REAL rendered trace (the transcript spine), not a toast.
 */
export function VerifyByTrace() {
	const router = useRouter();
	const [state, setState] = useState<State>("waiting");
	const [elapsed, setElapsed] = useState(0);
	const [errKind, setErrKind] = useState<ErrKind>("gateway");
	const done = useRef(false);

	useEffect(() => {
		let cancelled = false;
		let fails = 0;
		const start = Date.now();
		const clock = setInterval(() => {
			if (!cancelled && !done.current) {
				setElapsed(Math.floor((Date.now() - start) / 1000));
			}
		}, 1000);

		async function poll() {
			if (cancelled || done.current) return;
			try {
				const res = await fetch("/api/traces?limit=1", { cache: "no-store" });
				if (res.ok) {
					const data = (await res.json()) as {
						traces?: { trace_id: string }[];
					};
					const first = data.traces?.[0];
					if (first) {
						done.current = true;
						setState("found");
						// the magic moment: open the REAL rendered trace (transcript spine).
						window.setTimeout(() => {
							if (!cancelled) router.push(`/traces/${first.trace_id}`);
						}, 900);
						return;
					}
					fails = 0;
					setState("waiting"); // 200 + empty = genuinely "no trace yet"
				} else {
					fails += 1;
					if (fails >= 2) {
						setErrKind(
							res.status === 401 || res.status === 403 ? "auth" : "gateway",
						);
						setState("error");
					}
				}
			} catch {
				fails += 1;
				if (fails >= 2) {
					setErrKind("gateway");
					setState("error");
				}
			}
			if (!cancelled && !done.current) window.setTimeout(poll, POLL_MS);
		}
		void poll();

		return () => {
			cancelled = true;
			clearInterval(clock);
		};
	}, [router]);

	if (state === "found") {
		return (
			<div className="flex items-center gap-3 rounded-lg border border-seal-line bg-seal-soft/40 px-4 py-3">
				<span aria-hidden className="text-seal-ink">
					●
				</span>
				<div>
					<p className="text-sm font-medium text-ink">
						Your first trace landed
					</p>
					<p className="text-[13px] text-ink-2">Opening it…</p>
				</div>
			</div>
		);
	}

	if (state === "error") {
		return (
			<div
				role="alert"
				className="rounded-lg border border-danger/40 bg-danger-soft/40 px-4 py-3"
			>
				<p className="text-sm font-medium text-ink">
					{errKind === "auth"
						? "Your session was rejected"
						: "Can't reach the gateway"}
				</p>
				<p className="mt-0.5 text-[13px] text-ink-2">
					{errKind === "auth"
						? "Sign in again, then return to this step."
						: "The trace read path is unavailable right now — we'll keep trying. If your agent is already sending requests, the gateway or ingest may be down."}
				</p>
				<p className="mt-1 text-[11px] tabular-nums text-ink-3">
					Still polling… ({elapsed}s)
				</p>
			</div>
		);
	}

	return (
		<div className="rounded-lg border border-line bg-surface px-4 py-3">
			<div className="flex items-center gap-3">
				<span
					aria-hidden
					className="inline-block h-2 w-2 animate-pulse rounded-full bg-accent-ink"
				/>
				<p className="text-sm font-medium text-ink">
					Waiting for your first trace…{" "}
					<span className="tabular-nums text-ink-2">({elapsed}s)</span>
				</p>
			</div>
			<p className="mt-1 text-[13px] text-ink-2">
				Run the snippet above — the moment a span lands, this opens your trace.
			</p>
			{elapsed >= SLOW_AFTER_S && (
				<div className="mt-2 rounded-md border border-warn/30 bg-warn-soft/40 px-3 py-2 text-[12px] text-ink-2">
					<p className="font-medium text-warn">
						Nothing yet after {SLOW_AFTER_S}s? Check:
					</p>
					<ul className="mt-1 space-y-0.5">
						<li>• the snippet ran without an error</li>
						<li>• the base URL is your gateway URL (not the provider's)</li>
						<li>
							• you used the <code className="font-mono text-ink">tlane_</code>{" "}
							key shown above
						</li>
					</ul>
				</div>
			)}
		</div>
	);
}
