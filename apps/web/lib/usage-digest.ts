/**
 * usage-digest.ts — PLT-54: one plain-text usage digest a day to the operator inbox.
 *
 * Runs from the Worker's cron (`worker.ts` `scheduled`), outside any request, and uses the
 * Resend key the web Worker already holds. The cron schedule lives in `wrangler.jsonc`
 * (`triggers.crons`), and the windows and list cap live in `usage-digest.config.json`.
 *
 * Once per UTC day: every window ends at that day's `send_hour_utc` boundary, and both crons
 * send under the same `Idempotency-Key` (`usage-digest-YYYY-MM-DD`). If the 04:00 send reached
 * Resend, the 05:30 retry is answered as already sent: a 200 replay, or a 409 when its counts
 * drifted (`last_login_at` / `last_used_at` move after the boundary), which `sendEmail` treats as
 * delivered for a keyed send. If the 04:00 send never reached Resend, the retry sends. The
 * first-seen counts (people, workspaces, the new list) are stable across the two ticks; the
 * login and usage counts reflect the moment of the tick that actually sent.
 *
 * Observability: the skip/failure lines go to Workers Logs (observability is on). The on-node
 * watchdog that reads `TRACELANE_DEGRADED` does not see Worker logs, so a missing digest is
 * noticed by its absence in the inbox.
 *
 * Fail-OPEN (CLAUDE.md §10): a notice, never a control. `runUsageDigest` resolves, never
 * rejects. Logs carry no address.
 *
 * Dependency-free beyond the Neon driver on purpose: `worker.ts` bundles this file with
 * wrangler, outside the Next.js build, so it imports no `@/` alias and no Next module.
 */

import { neon } from "@neondatabase/serverless";
import { sendEmail } from "./email";
import {
	OPERATOR_INBOX,
	plainAddress,
	sanitizeUserText,
} from "./operator-notice";
import config from "./usage-digest.config.json";

export interface UsageCounts {
	peopleTotal: number;
	peopleNew24h: number;
	peopleNew7d: number;
	logins24h: number;
	logins7d: number;
	workspacesTotal: number;
	workspacesNew24h: number;
	workspacesNew7d: number;
	activeWorkspaces24h: number;
	activeWorkspaces7d: number;
	/** Newest first, at most `max_listed_signups + 1` (the extra row only proves "more"). */
	newPeople: string[];
}

export type DigestResult = "sent" | "skipped" | "failed";

/** The instant a day's windows end: that UTC date at the configured send hour. */
export function windowEnd(at: Date, sendHour = config.send_hour_utc): Date {
	return new Date(
		Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate(), sendHour),
	);
}

export function dayIso(end: Date): string {
	return end.toISOString().slice(0, 10);
}

export function idempotencyKey(end: Date): string {
	return `usage-digest-${dayIso(end)}`;
}

export function recipient(configured: string | undefined): string | null {
	const to = configured || OPERATOR_INBOX;
	return plainAddress(to) ? to : null;
}

/** Subject and plain-text body. Counts and the new people's addresses only; no internal IDs. */
export function render(
	end: Date,
	c: UsageCounts,
	maxListed = config.max_listed_signups,
): { subject: string; text: string } {
	const day = dayIso(end);
	const lines = [
		`People: ${c.peopleTotal} total · ${c.peopleNew24h} new in 24 h · ${c.peopleNew7d} new in 7 d`,
		`Logged in: ${c.logins24h} in 24 h · ${c.logins7d} in 7 d`,
		`Workspaces: ${c.workspacesTotal} total · ${c.workspacesNew24h} new in 24 h · ${c.workspacesNew7d} new in 7 d`,
		`Workspaces that used the gateway: ${c.activeWorkspaces24h} in 24 h · ${c.activeWorkspaces7d} in 7 d`,
	];
	if (c.peopleNew24h > 0) {
		lines.push("", "New people (24 h):");
		const shown = c.newPeople.slice(0, maxListed);
		for (const email of shown) lines.push(`- ${sanitizeUserText(email, 320)}`);
		const more = c.peopleNew24h - shown.length;
		if (more > 0) lines.push(`…and ${more} more`);
	}
	const endLabel = `${day} ${end.toISOString().slice(11, 16)}`;
	lines.push(
		"",
		`Windows end ${endLabel} UTC. Counts include the operator's own accounts.`,
		"",
	);
	return { subject: `Tracelane usage — ${day} (UTC)`, text: lines.join("\n") };
}

/** A tagged-template SQL runner (the Neon driver's shape), injectable for tests. */
export type SqlRunner = (
	strings: TemplateStringsArray,
	...values: unknown[]
) => Promise<Record<string, unknown>[]>;

const toNumber = (v: unknown): number => Number(v ?? 0);

function escapeHtml(s: string): string {
	return s.replace(
		/[&<>"']/g,
		(c) =>
			({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
				c
			] ?? c,
	);
}

/** All counts in ONE statement over windows ending at `end` (exclusive). */
export async function queryCounts(
	sql: SqlRunner,
	end: Date,
	maxListed = config.max_listed_signups,
): Promise<UsageCounts> {
	const e = end.toISOString();
	const limit = maxListed + 1;
	const rows = await sql`
		SELECT
		  (SELECT count(*) FROM signups WHERE first_seen_at < ${e}::timestamptz) AS people_total,
		  (SELECT count(*) FROM signups WHERE first_seen_at >= ${e}::timestamptz - interval '24 hours' AND first_seen_at < ${e}::timestamptz) AS people_new_24h,
		  (SELECT count(*) FROM signups WHERE first_seen_at >= ${e}::timestamptz - interval '7 days' AND first_seen_at < ${e}::timestamptz) AS people_new_7d,
		  (SELECT count(*) FROM signups WHERE last_login_at >= ${e}::timestamptz - interval '24 hours' AND last_login_at < ${e}::timestamptz) AS logins_24h,
		  (SELECT count(*) FROM signups WHERE last_login_at >= ${e}::timestamptz - interval '7 days' AND last_login_at < ${e}::timestamptz) AS logins_7d,
		  (SELECT count(*) FROM tenants WHERE created_at < ${e}::timestamptz) AS workspaces_total,
		  (SELECT count(*) FROM tenants WHERE created_at >= ${e}::timestamptz - interval '24 hours' AND created_at < ${e}::timestamptz) AS workspaces_new_24h,
		  (SELECT count(*) FROM tenants WHERE created_at >= ${e}::timestamptz - interval '7 days' AND created_at < ${e}::timestamptz) AS workspaces_new_7d,
		  (SELECT count(DISTINCT tenant_id) FROM api_keys WHERE last_used_at >= ${e}::timestamptz - interval '24 hours' AND last_used_at < ${e}::timestamptz) AS active_24h,
		  (SELECT count(DISTINCT tenant_id) FROM api_keys WHERE last_used_at >= ${e}::timestamptz - interval '7 days' AND last_used_at < ${e}::timestamptz) AS active_7d,
		  ARRAY(SELECT email FROM signups WHERE first_seen_at >= ${e}::timestamptz - interval '24 hours' AND first_seen_at < ${e}::timestamptz ORDER BY first_seen_at DESC, email LIMIT ${limit}) AS new_people`;
	const r = rows[0] ?? {};
	return {
		peopleTotal: toNumber(r.people_total),
		peopleNew24h: toNumber(r.people_new_24h),
		peopleNew7d: toNumber(r.people_new_7d),
		logins24h: toNumber(r.logins_24h),
		logins7d: toNumber(r.logins_7d),
		workspacesTotal: toNumber(r.workspaces_total),
		workspacesNew24h: toNumber(r.workspaces_new_24h),
		workspacesNew7d: toNumber(r.workspaces_new_7d),
		activeWorkspaces24h: toNumber(r.active_24h),
		activeWorkspaces7d: toNumber(r.active_7d),
		newPeople: Array.isArray(r.new_people) ? r.new_people.map(String) : [],
	};
}

export interface DigestDeps {
	sql?: SqlRunner;
	send?: typeof sendEmail;
	/** The cron's `env` bindings: a fallback when `process.env` is not populated. */
	env?: Record<string, unknown>;
}

/** Run one digest for the cron tick at `scheduledAt`. Resolves, never rejects. */
export async function runUsageDigest(
	scheduledAt: Date,
	deps: DigestDeps = {},
): Promise<DigestResult> {
	const end = windowEnd(scheduledAt);
	try {
		const env = (k: string): string | undefined => {
			const v = process.env[k] || deps.env?.[k];
			if (typeof v === "string" && v) {
				// sendEmail reads process.env; bridge a binding-only value once.
				if (!process.env[k]) process.env[k] = v;
				return v;
			}
			return undefined;
		};
		const to = recipient(env("USAGE_DIGEST_TO") || env("SIGNUP_ALERT_TO"));
		const from = env("RESEND_FROM");
		const url = env("DATABASE_URL");
		if (!to || !from || !env("RESEND_API_KEY") || (!url && !deps.sql)) {
			console.warn(
				JSON.stringify({
					event: "usage_digest_skipped",
					marker: "TRACELANE_DEGRADED usage_digest_unconfigured",
					reason: !to
						? "recipient not one plain address"
						: !from
							? "RESEND_FROM unset"
							: !env("RESEND_API_KEY")
								? "RESEND_API_KEY unset"
								: "DATABASE_URL unset",
				}),
			);
			return "skipped";
		}
		const sql = deps.sql ?? (neon(url as string) as unknown as SqlRunner);
		const counts = await queryCounts(sql, end);
		const { subject, text } = render(end, counts);
		const ok = await (deps.send ?? sendEmail)({
			to,
			from,
			subject,
			text,
			html: `<pre style="font-family:monospace">${escapeHtml(text)}</pre>`,
			idempotencyKey: idempotencyKey(end),
		});
		console.log(
			JSON.stringify({
				event: ok ? "usage_digest_sent" : "usage_digest_failed",
				day: dayIso(end),
			}),
		);
		return ok ? "sent" : "failed";
	} catch (err) {
		console.error(
			JSON.stringify({
				event: "usage_digest_failed",
				day: dayIso(end),
				error: err instanceof Error ? err.name : "unknown",
			}),
		);
		return "failed";
	}
}
