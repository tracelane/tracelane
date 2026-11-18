"use client";

import { signOutNow } from "@/lib/sign-out";
import { type ReactNode, useState } from "react";

export function SignOutButton({
	children = "Sign out",
	className,
	title,
}: {
	children?: ReactNode;
	className?: string;
	title?: string;
}) {
	const [pending, setPending] = useState(false);
	const [failed, setFailed] = useState(false);
	return (
		<>
			<button
				type="button"
				title={title}
				aria-label="Sign out"
				className={className}
				disabled={pending}
				onClick={async () => {
					setPending(true);
					setFailed(false);
					try {
						await signOutNow();
					} catch {
						setFailed(true);
						setPending(false);
					}
				}}
			>
				{pending ? "Signing out…" : children}
			</button>
			{failed && (
				<p role="alert" className="text-xs text-danger-ink">
					Could not sign out — try again
				</p>
			)}
		</>
	);
}
