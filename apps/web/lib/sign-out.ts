/** POST first, then navigate outside the form-action redirect chain. */
export async function signOutNow(): Promise<void> {
	const response = await fetch("/sign-out", {
		method: "POST",
		credentials: "same-origin",
		cache: "no-store",
	});
	if (!response.ok) throw new Error("Could not sign out — try again");
	const { logout_url: target } = (await response.json()) as {
		logout_url?: unknown;
	};
	if (
		typeof target !== "string" ||
		(target !== "/sign-in" && !target.startsWith("https://"))
	) {
		throw new Error("Could not sign out — try again");
	}
	window.location.assign(target);
}
