"use client";

/**
 * EmailChangeForm — self-serve email change (SET-26).
 *
 * Three fields, because three confirmations are the whole security control at
 * launch (there is no re-auth prompt yet — IDENTITY_TEAM_SPEC §6 accepts
 * type-to-confirm): the new address, the new address again, and the CURRENT
 * address retyped. `canSubmitEmailChange` is the same rule set the server
 * enforces, so the button is never live on a request the server would refuse —
 * and the server refuses it anyway, because a disabled button is not a control.
 *
 * Deliberately plain `useState` + `fetch` rather than the react-query mutation
 * the sibling name form uses: this component carries the account's most
 * dangerous action, and being renderable with no provider context is what lets
 * its rendered shape be asserted directly in a test.
 */

import {
	EMAIL_CHANGE_ENDPOINT,
	canSubmitEmailChange,
} from "@/app/settings/account/email/validate";
import { useState } from "react";

interface ChangeResult {
	email: string;
	verificationSent: boolean;
}

const FIELD =
	"w-full rounded-lg bg-surface-2 border border-line px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring";

export function EmailChangeForm({ email }: { email: string }) {
	const [newEmail, setNewEmail] = useState("");
	const [confirmEmail, setConfirmEmail] = useState("");
	const [confirmCurrentEmail, setConfirmCurrentEmail] = useState("");
	const [pending, setPending] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [done, setDone] = useState<ChangeResult | null>(null);

	const ready = canSubmitEmailChange({
		currentEmail: email,
		newEmail,
		confirmEmail,
		confirmCurrentEmail,
	});

	async function submit() {
		setPending(true);
		setError(null);
		try {
			const res = await fetch(EMAIL_CHANGE_ENDPOINT, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ newEmail, confirmEmail, confirmCurrentEmail }),
			});
			const body = (await res.json().catch(() => ({}))) as {
				email?: string;
				verificationSent?: boolean;
				error?: string;
				detail?: string;
			};
			if (!res.ok) {
				setError(body.detail ?? body.error ?? `HTTP ${res.status}`);
				return;
			}
			setDone({
				email: body.email ?? newEmail,
				verificationSent: !!body.verificationSent,
			});
			setNewEmail("");
			setConfirmEmail("");
			setConfirmCurrentEmail("");
		} catch {
			setError("could not reach the server — try again");
		} finally {
			setPending(false);
		}
	}

	if (done) {
		return (
			<section className="space-y-2 rounded-lg border border-line p-4">
				<h3 className="text-xs font-semibold text-ink">Email changed</h3>
				<p className="text-xs text-ink-2">
					Your account address is now{" "}
					<span className="font-mono text-ink">{done.email}</span>.
				</p>
				<p className="text-xs text-ink-2">
					{done.verificationSent
						? "We sent a verification message to the new address. Confirm it to finish — until you do, the address is on file but not verified."
						: "The new address is not verified yet. Signing in again will send the verification message."}
				</p>
				<p className="text-xs text-ink-3">
					Your current session still carries the old address. Sign out and back
					in to refresh it — you will sign in with the new address, and
					verification goes there, so check that you can receive mail at it
					before you sign out.
				</p>
				<a
					href="/sign-out"
					className="inline-block rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
				>
					Sign out
				</a>
			</section>
		);
	}

	return (
		<section className="space-y-2" data-testid="email-change">
			<h3 className="text-xs font-semibold text-ink">Change email</h3>
			<p className="text-xs text-ink-2">
				Your sign-in address and where account recovery goes. The new address
				must be verified before it is trusted, and you will sign in with it from
				then on — so use an address you can already receive mail at.
			</p>

			<label htmlFor="new-email" className="block pt-1 text-xs text-ink-2">
				New email
			</label>
			<input
				id="new-email"
				type="email"
				autoComplete="off"
				value={newEmail}
				onChange={(e) => setNewEmail(e.target.value)}
				placeholder="you@example.com"
				className={FIELD}
			/>

			<label
				htmlFor="new-email-confirm"
				className="block pt-1 text-xs text-ink-2"
			>
				New email again
			</label>
			<input
				id="new-email-confirm"
				type="email"
				autoComplete="off"
				value={confirmEmail}
				onChange={(e) => setConfirmEmail(e.target.value)}
				placeholder="you@example.com"
				className={FIELD}
			/>

			<label
				htmlFor="current-email-confirm"
				className="block pt-1 text-xs text-ink-2"
			>
				Type your current email to confirm
			</label>
			<input
				id="current-email-confirm"
				type="email"
				autoComplete="off"
				value={confirmCurrentEmail}
				onChange={(e) => setConfirmCurrentEmail(e.target.value)}
				placeholder={email}
				className={FIELD}
			/>

			<div className="flex items-center gap-3 pt-1">
				<button
					type="button"
					disabled={!ready || pending}
					onClick={submit}
					className="rounded-lg bg-action px-3 py-1.5 text-xs font-medium text-action-on transition-colors hover:bg-action/90 disabled:cursor-not-allowed disabled:opacity-40"
				>
					{pending ? "Changing…" : "Change email"}
				</button>
				{error && <span className="text-xs text-danger-ink">{error}</span>}
			</div>
		</section>
	);
}
