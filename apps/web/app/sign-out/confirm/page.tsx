import { SignOutButton } from "@/components/SignOutButton";

export default function SignOutConfirmation() {
	return (
		<div className="min-h-screen grid place-items-center bg-bg p-6">
			<div className="space-y-4 text-sm">
				<h1>Sign out of Tracelane?</h1>
				<SignOutButton className="bg-action px-4 py-2 text-action-on" />
				<a href="/" className="ml-4">
					Cancel
				</a>
			</div>
		</div>
	);
}
