"use client";
/**
 * OG-60 — the client seam every Gateway settings page shares: the typed fetch over the
 * dashboard's control relay, the role context, and the loading / forbidden / not-configured /
 * error boundary (`specs/OG-60-…md` §4). One file so no page invents its own states.
 */

import { apiFetchRaw } from "@/lib/api-fetch";
import {
	type Refusal,
	describeRefusal,
	disabledReason,
} from "@/lib/gateway-controls";
import {
	type CapabilitySlug,
	roleCan,
} from "@/lib/role-capabilities.generated";
import {
	type UseQueryResult,
	useMutation,
	useQuery,
	useQueryClient,
} from "@tanstack/react-query";
import { Button, ErrorState, Skeleton } from "@tracelanedev/ui";
import { type ReactNode, createContext, useContext } from "react";

export const CONTROL_BASE = "/api/settings/gateway-control";

// ── Role ─────────────────────────────────────────────────────────────────────

const RoleContext = createContext<string | null>(null);

/** The signed-in user's WorkOS role slug, from the server layout. UI gating only. */
export function RoleProvider({
	role,
	children,
}: { role: string | null; children: ReactNode }) {
	return <RoleContext.Provider value={role}>{children}</RoleContext.Provider>;
}

/** `{allowed, reason}` — the reason is shown beside a disabled control. */
export function useCan(cap: CapabilitySlug): {
	allowed: boolean;
	reason: string | null;
} {
	const role = useContext(RoleContext);
	const allowed = roleCan(role, cap);
	return { allowed, reason: allowed ? null : disabledReason(cap) };
}

// ── Fetch ────────────────────────────────────────────────────────────────────

export class ControlError extends Error {
	constructor(
		readonly status: number,
		readonly refusal: Refusal,
		readonly body: Record<string, unknown> | null,
	) {
		super(refusal.message);
		this.name = "ControlError";
	}
}

type Verb = "GET" | "PUT" | "POST" | "PATCH" | "DELETE";

/** One call to `url` (our own `/api/*`). A non-2xx throws a `ControlError` carrying the wording. */
export async function requestJson<T>(
	verb: Verb,
	url: string,
	body?: unknown,
): Promise<T> {
	let res: Response;
	try {
		res = await apiFetchRaw(url, {
			method: verb,
			...(body === undefined
				? {}
				: {
						headers: { "content-type": "application/json" },
						body: JSON.stringify(body),
					}),
		});
	} catch (err) {
		if (err instanceof ControlError) throw err;
		const refusal = describeRefusal(503, null);
		throw new ControlError(503, refusal, null);
	}
	if (!res.ok) {
		const parsed = (await res.json().catch(() => null)) as Record<
			string,
			unknown
		> | null;
		throw new ControlError(
			res.status,
			describeRefusal(res.status, parsed),
			parsed,
		);
	}
	if (res.status === 204) return undefined as T;
	return (await res.json()) as T;
}

/** One call through the control relay. */
export function controlRequest<T>(
	verb: Verb,
	path: string,
	body?: unknown,
): Promise<T> {
	return requestJson<T>(verb, `${CONTROL_BASE}/${path}`, body);
}

export function useControlQuery<T>(
	path: string,
	opts: { enabled?: boolean } = {},
): UseQueryResult<T, ControlError> {
	return useQuery<T, ControlError>({
		queryKey: ["gateway-control", path],
		queryFn: () => controlRequest<T>("GET", path),
		retry: false,
		staleTime: 0,
		...opts,
	});
}

/** A write that refreshes the named read paths when it lands. */
export function useControlWrite<TRes = unknown, TBody = unknown>(
	verb: Exclude<Verb, "GET">,
	path: string | ((b: TBody) => string),
	invalidate: string[] = [],
) {
	const qc = useQueryClient();
	return useMutation<TRes, ControlError, TBody>({
		mutationFn: (b) =>
			controlRequest<TRes>(
				verb,
				typeof path === "function" ? path(b) : path,
				b,
			),
		onSuccess: async () => {
			await Promise.all(
				invalidate.map((p) =>
					qc.invalidateQueries({ queryKey: ["gateway-control", p] }),
				),
			);
		},
	});
}

// ── States ───────────────────────────────────────────────────────────────────

/** Skeleton of the final layout, never a spinner that can run forever. */
export function LoadingBlock({ rows = 3 }: { rows?: number }) {
	return (
		<div aria-busy="true" aria-label="Loading" className="space-y-2">
			{Array.from({ length: rows }, (_, i) => (
				// biome-ignore lint/suspicious/noArrayIndexKey: static skeleton rows
				<Skeleton key={i} className="h-10 w-full" />
			))}
		</div>
	);
}

/**
 * The read boundary. Error is never empty (`TRAPS.md` §18): a 403 names the role, a 404
 * names the missing control plane, anything else is a retryable error with its status.
 */
export function Boundary<T>({
	query,
	resource,
	children,
	rows,
}: {
	query: UseQueryResult<T, ControlError>;
	resource: string;
	children: (data: T) => ReactNode;
	rows?: number;
}) {
	if (query.isPending) return <LoadingBlock rows={rows} />;
	if (query.isError) {
		const e = query.error;
		const k = e.refusal.kind;
		const title =
			k === "forbidden" || k === "ip_blocked" || k === "sso_required"
				? `You can't view ${resource}`
				: k === "no_control_plane"
					? `${resource} needs a control plane`
					: `Couldn't load ${resource}`;
		return (
			<ErrorState
				title={title}
				description={`${e.refusal.message}${e.status ? ` (HTTP ${e.status})` : ""}`}
				action={
					k === "forbidden" || k === "no_control_plane" ? undefined : (
						<Button size="sm" onClick={() => void query.refetch()}>
							Retry
						</Button>
					)
				}
			/>
		);
	}
	return <>{children(query.data as T)}</>;
}

/** A write's refusal, beside the form — the gateway's code and message verbatim. */
export function RefusalNote({
	error,
	fieldOnly,
}: {
	error: ControlError | null | undefined;
	/** Show only a refusal that names no field (field refusals render at the field). */
	fieldOnly?: boolean;
}) {
	if (!error) return null;
	if (fieldOnly && error.refusal.field) return null;
	return (
		<p role="alert" className="text-sm text-danger-ink">
			{error.refusal.message}
			{error.refusal.code ? (
				<span className="ml-1 font-mono text-xs text-ink-3">
					{error.refusal.code}
				</span>
			) : null}
			{error.refusal.kind === "paused" ? (
				<>
					{" "}
					<a className="underline" href="/settings/gateway/emergency">
						Emergency controls
					</a>
				</>
			) : null}
		</p>
	);
}
