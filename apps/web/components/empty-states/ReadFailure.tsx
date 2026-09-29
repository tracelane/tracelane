import { EmptyState } from "@tracelanedev/ui";

/** Failed reads never establish that a workspace has no data. */
export function ReadFailure({
	status,
	resource,
	retryHref,
}: { status: number; resource: string; retryHref: string }) {
	return (
		<EmptyState
			title={
				status === 401
					? "Sign in to continue"
					: status === 403
						? "Access denied"
						: `Couldn't load ${resource}`
			}
			description={
				status === 401
					? "Your session could not be authorized. Sign in and try again."
					: status === 403
						? "Your role cannot read this data. Ask a workspace owner to check your access."
						: "This read failed. Your data may still be available; retry to check."
			}
			action={
				<a
					className="text-sm underline"
					href={status === 401 ? "/sign-in" : retryHref}
				>
					{status === 401 ? "Sign in" : "Retry"}
				</a>
			}
		/>
	);
}
