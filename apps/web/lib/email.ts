/**
 * email.ts — transactional billing emails (BILL-01 / ADR-076 item 8, web half).
 *
 * Behind `RESEND_API_KEY`. Unset ⇒ log ONE warn per process carrying the
 * stable `TRACELANE_DEGRADED email_unconfigured` marker (`.claude/rules/
 * logging.md`: "enter the degraded state → one WARN … not a line per
 * occurrence") and return — NEVER throw. A missing mail provider must not
 * turn a webhook 200 into a 503 and stop a real plan change from applying.
 *
 * Raw `fetch` against Resend's HTTP API — no new dependency (`resend` is not
 * added to package.json; a single POST is not worth a client library here).
 *
 * Usage-warning emails (75%/90% of a meter) are the GATEWAY's job, not this
 * file's — spec `BILL-01` build brief, item 8.
 */

const RESEND_API = "https://api.resend.com/emails";
const FROM = "Tracelane Billing <billing@tracelane.dev>";

let warnedUnconfigured = false;

/** Log the degradation marker exactly ONCE per process (`.claude/rules/logging.md`). */
function noteUnconfigured(): void {
	if (warnedUnconfigured) return;
	warnedUnconfigured = true;
	console.warn(
		"TRACELANE_DEGRADED email_unconfigured — RESEND_API_KEY is not set; billing emails are not being sent.",
	);
}

export interface SendEmailInput {
	to: string;
	subject: string;
	html: string;
	text: string;
}

/**
 * Send one email via Resend. Fail-open: on a missing key, a non-2xx
 * response, or a network error, this logs and returns `false` — it never
 * throws, so a caller in a webhook handler can fire-and-forget without
 * risking the plan-state write that triggered it.
 */
export async function sendEmail(input: SendEmailInput): Promise<boolean> {
	const key = process.env.RESEND_API_KEY;
	if (!key) {
		noteUnconfigured();
		return false;
	}
	try {
		const res = await fetch(RESEND_API, {
			method: "POST",
			headers: {
				authorization: `Bearer ${key}`,
				"content-type": "application/json",
			},
			body: JSON.stringify({
				from: FROM,
				to: [input.to],
				subject: input.subject,
				html: input.html,
				text: input.text,
			}),
		});
		if (!res.ok) {
			// Never log the response body — provider error JSON can echo the
			// request, and this runs on the same paths `.claude/rules/security.md`'s
			// provider-adapter leak rule governs.
			console.error(`[email] Resend send failed: ${res.status}`);
			return false;
		}
		return true;
	} catch (err) {
		console.error(
			"[email] Resend send threw:",
			err instanceof Error ? err.message : err,
		);
		return false;
	}
}

const PLAN_LABEL: Record<string, string> = {
	free: "Free",
	builder: "Builder",
	team: "Team",
	business: "Business",
	enterprise: "Enterprise",
};

/** Dunning started (day 1 of the retry schedule) — spec §0.5, billing_policy.dunning_retry_days. */
export async function sendDunningStartedEmail(
	to: string,
	opts: { plan: string; retryDays: number[] },
): Promise<boolean> {
	const planName = PLAN_LABEL[opts.plan] ?? opts.plan;
	const schedule = opts.retryDays.join(", ");
	return sendEmail({
		to,
		subject: "Tracelane — we could not process your last payment",
		html: `<p>We could not process your last payment for your ${planName} plan.</p><p>We will retry on days ${schedule} after the failed charge. Your ${planName} plan stays active and ingest is not affected while we retry — update your payment method in the billing portal to avoid an interruption.</p>`,
		text: `We could not process your last payment for your ${planName} plan. We will retry on days ${schedule} after the failed charge. Your ${planName} plan stays active and ingest is not affected while we retry — update your payment method in the billing portal to avoid an interruption.`,
	});
}

/** Dropped to Free after dunning is exhausted — spec §0.5, billing_policy.dunning_data_hold_days. */
export async function sendDroppedToFreeEmail(
	to: string,
	opts: { previousPlan: string; dataHoldUntil: Date },
): Promise<boolean> {
	const planName = PLAN_LABEL[opts.previousPlan] ?? opts.previousPlan;
	const holdDate = opts.dataHoldUntil.toISOString().slice(0, 10);
	return sendEmail({
		to,
		subject: "Tracelane — your workspace moved to the Free plan",
		html: `<p>We were unable to collect payment for your ${planName} plan, so your workspace has moved to the Free plan.</p><p>Your data is held until <strong>${holdDate}</strong> — resubscribe before then to keep everything. Ingest was never blocked during this process.</p>`,
		text: `We were unable to collect payment for your ${planName} plan, so your workspace has moved to the Free plan. Your data is held until ${holdDate} — resubscribe before then to keep everything. Ingest was never blocked during this process.`,
	});
}

/** A plan change (upgrade, downgrade, or interval switch) took effect. */
export async function sendPlanChangedEmail(
	to: string,
	opts: { fromPlan: string; toPlan: string },
): Promise<boolean> {
	const from = PLAN_LABEL[opts.fromPlan] ?? opts.fromPlan;
	const to_ = PLAN_LABEL[opts.toPlan] ?? opts.toPlan;
	return sendEmail({
		to,
		subject: `Tracelane — your plan changed to ${to_}`,
		html: `<p>Your Tracelane workspace moved from ${from} to <strong>${to_}</strong>.</p><p>New limits apply to API traffic within 15 minutes.</p>`,
		text: `Your Tracelane workspace moved from ${from} to ${to_}. New limits apply to API traffic within 15 minutes.`,
	});
}
