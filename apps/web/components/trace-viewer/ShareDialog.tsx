"use client";

/**
 * OBS-48 — the "Share" header action + dialog on the authenticated trace page.
 *
 * Same shape as `TraceFlag`/`TraceFlagPanel`: an inline panel toggled from a
 * header button (this app has no Dialog/Modal primitive — `packages/ui` ships
 * none — so the flag control is the existing pattern for "a header action that
 * opens a small form", and this reuses it rather than inventing a new one).
 *
 * The gateway owns the store, the tenant check, the mint/list/revoke logic, the
 * content denylist and the 10-active-links cap (spec §2/§5). This component
 * validates nothing beyond what the picker already constrains.
 *
 * ── WHY OLDER LINKS HAVE NO COPYABLE URL, AND THE SPEC DOES NOT SAY SO ───────
 * `trace_shares.token_hash` stores only `sha256(token)` (spec §2, migration
 * `0036_trace_shares.sql`) — the raw token is never persisted anywhere, so it
 * cannot be recovered later. `GET /v1/traces/{id}/shares` (spec §2) returns
 * `{id, created_at, expires_at, view_count}` with NO token and NO url field,
 * which means the full `/s/<token>` URL literally cannot be reconstructed for
 * a link that was not JUST minted in this session — the same "shown once"
 * shape this codebase already uses for `api_keys` (full key returned only at
 * mint time, `argon2idPhc` stored thereafter). The §8 wireframe shows a URL
 * next to every active link including ones with an established view count,
 * which is the shape THIS FILE COULD NOT BUILD AS DRAWN without either (a)
 * storing the token in the clear (a real security regression: anyone who can
 * read `trace_shares` could then impersonate every open share) or (b)
 * inventing a second, undocumented endpoint. Older rows show id/created/expiry
 * /views/Revoke; only the just-minted link (held in local state, from the
 * `POST` response) gets a full copyable URL, with a one-time-only note.
 */

import { CopyButton } from "@/components/trace-viewer/CopyButton";
import { Button, SegmentedControl } from "@tracelanedev/ui";
import { useEffect, useState } from "react";

export type ShareLink = {
	id: string;
	created_at: string;
	expires_at: string;
	view_count: number;
};

type ShareMintResult = {
	id: string;
	token: string;
	url: string;
	expires_at: string;
};

type ExpiryDays = "7" | "30" | "90";

const EXPIRY_OPTIONS: ReadonlyArray<{ value: ExpiryDays; label: string }> = [
	{ value: "7", label: "7d" },
	{ value: "30", label: "30d" },
	{ value: "90", label: "90d" },
];

/** Pure: remove one link by id. Exported so the revoke path is unit-testable
 * without a DOM (this repo's vitest runs in the `node` environment — no
 * jsdom/user-event — so interaction is proven at the state-transition level). */
export function removeLink(links: ShareLink[], id: string): ShareLink[] {
	return links.filter((l) => l.id !== id);
}

/** Prepend a freshly-minted link's list-shape row (no `view_count` yet — 0). */
export function withMinted(
	links: ShareLink[],
	minted: ShareMintResult,
): ShareLink[] {
	return [
		{
			id: minted.id,
			created_at: new Date().toISOString(),
			expires_at: minted.expires_at,
			view_count: 0,
		},
		...links,
	];
}

/**
 * Map a failed mint/list/revoke response to the sentence the dialog shows.
 * 403 always becomes the same permission sentence (spec §4: "a member without
 * `read` gets the gateway 403 verbatim in the dialog" — read as "a permission
 * message, not a generic failure", per the build brief); every other status
 * shows the gateway's own message when it sent one, falling back to a generic
 * sentence that still tells the truth ("nothing was recorded").
 */
export function shareErrorMessage(
	status: number,
	body: { error?: unknown } | null,
): string {
	if (status === 403) {
		return "Your role doesn't have permission to share this trace.";
	}
	if (body && typeof body.error === "string" && body.error.length > 0) {
		return body.error;
	}
	return "Couldn't complete that action. Nothing was recorded.";
}

/** Days from now until `iso`, floored — never negative. */
function daysUntil(iso: string, nowMs = Date.now()): number {
	const ms = new Date(iso).getTime() - nowMs;
	return Math.max(0, Math.floor(ms / 86_400_000));
}

async function parseError(res: Response): Promise<string> {
	let body: { error?: unknown } | null = null;
	try {
		body = (await res.json()) as { error?: unknown };
	} catch {
		body = null;
	}
	return shareErrorMessage(res.status, body);
}

/** One row: a link the owner can Revoke, with a copyable URL ONLY when it was
 * minted THIS session (see the file header for why older rows cannot have one). */
export function ShareLinkRow({
	link,
	mintedUrl,
	revoking,
	onRevoke,
}: {
	link: ShareLink;
	/** The full `/s/<token>` URL — present only for the row just minted. */
	mintedUrl?: string;
	revoking: boolean;
	onRevoke: (id: string) => void;
}) {
	const expiresIn = daysUntil(link.expires_at);
	return (
		<div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-line px-2.5 py-1.5 text-sm">
			<div className="min-w-0 flex-1">
				{mintedUrl ? (
					<div className="flex items-center gap-1.5">
						<span className="truncate font-mono text-xs text-ink">
							{mintedUrl}
						</span>
						<CopyButton value={mintedUrl} />
					</div>
				) : (
					<span className="text-ink-2">
						Created {new Date(link.created_at).toLocaleDateString()}
					</span>
				)}
				<div className="text-2xs text-ink-3">
					{link.view_count} view{link.view_count === 1 ? "" : "s"} · expires in{" "}
					{expiresIn} day{expiresIn === 1 ? "" : "s"}
				</div>
			</div>
			<Button
				type="button"
				variant="ghost"
				size="sm"
				disabled={revoking}
				onClick={() => onRevoke(link.id)}
			>
				{revoking ? "Revoking…" : "Revoke"}
			</Button>
		</div>
	);
}

export function ShareDialog({ traceId }: { traceId: string }) {
	const [open, setOpen] = useState(false);
	const [expiry, setExpiry] = useState<ExpiryDays>("30");
	const [links, setLinks] = useState<ShareLink[] | null>(null);
	const [mintedUrls, setMintedUrls] = useState<Record<string, string>>({});
	const [listError, setListError] = useState<string | null>(null);
	const [mintError, setMintError] = useState<string | null>(null);
	const [minting, setMinting] = useState(false);
	const [revokingId, setRevokingId] = useState<string | null>(null);

	// Load the active-links list once, the first time the panel opens.
	useEffect(() => {
		if (!open || links !== null) return;
		let cancelled = false;
		(async () => {
			try {
				const res = await fetch(
					`/api/traces/${encodeURIComponent(traceId)}/shares`,
				);
				if (!res.ok) {
					if (!cancelled) setListError(await parseError(res));
					return;
				}
				const data = (await res.json()) as ShareLink[];
				if (!cancelled) setLinks(data);
			} catch {
				if (!cancelled) {
					setListError("Couldn't reach the server. Active links unknown.");
				}
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [open, links, traceId]);

	async function mint() {
		setMinting(true);
		setMintError(null);
		try {
			const res = await fetch(
				`/api/traces/${encodeURIComponent(traceId)}/shares`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ expires_in_days: Number(expiry) }),
				},
			);
			if (!res.ok) {
				setMintError(await parseError(res));
				return;
			}
			const created = (await res.json()) as ShareMintResult;
			setLinks((prev) => withMinted(prev ?? [], created));
			setMintedUrls((prev) => ({ ...prev, [created.id]: created.url }));
		} catch {
			setMintError("Couldn't reach the server. The link was not created.");
		} finally {
			setMinting(false);
		}
	}

	async function revoke(id: string) {
		setRevokingId(id);
		setMintError(null);
		try {
			const res = await fetch(
				`/api/traces/${encodeURIComponent(traceId)}/shares/${encodeURIComponent(id)}`,
				{ method: "DELETE" },
			);
			if (!res.ok && res.status !== 404) {
				setMintError(await parseError(res));
				return;
			}
			setLinks((prev) => removeLink(prev ?? [], id));
		} catch {
			setMintError("Couldn't reach the server. The link was not revoked.");
		} finally {
			setRevokingId(null);
		}
	}

	return (
		<div className="relative inline-block">
			<Button
				type="button"
				variant="secondary"
				size="sm"
				onClick={() => setOpen((v) => !v)}
			>
				Share
			</Button>

			{open && (
				<div className="absolute right-0 z-10 mt-1.5 w-80 space-y-3 rounded-lg border border-line bg-surface p-3 shadow-[var(--shadow-card)]">
					<SegmentedControl
						label="Link expiry"
						value={expiry}
						onChange={setExpiry}
						options={EXPIRY_OPTIONS}
						size="sm"
					/>
					{/* Fixed sentence, verbatim — spec §2/§4. No opt-in ever exists for
					    content, so this line does not change with the expiry choice. */}
					<p className="text-2xs text-ink-3">
						Prompts, responses and tool bodies are never included.
					</p>
					<Button
						type="button"
						variant="primary"
						size="sm"
						disabled={minting}
						onClick={mint}
					>
						{minting ? "Creating…" : "Create link"}
					</Button>

					{mintError && (
						<p role="alert" className="text-sm text-danger-ink">
							{mintError}
						</p>
					)}

					<div className="space-y-1.5 border-t border-line pt-2">
						{listError ? (
							<p role="alert" className="text-sm text-danger-ink">
								{listError}
							</p>
						) : links === null ? (
							<p className="text-sm text-ink-3">Loading…</p>
						) : links.length === 0 ? (
							<p className="text-sm text-ink-3">No links yet</p>
						) : (
							links.map((l) => (
								<ShareLinkRow
									key={l.id}
									link={l}
									mintedUrl={mintedUrls[l.id]}
									revoking={revokingId === l.id}
									onRevoke={revoke}
								/>
							))
						)}
					</div>
				</div>
			)}
		</div>
	);
}
