/** `1,284` — grouped integer. Non-finite → `—`. */
export function fmtCount(n: number | string | null | undefined): string {
	if (typeof n === "string")
		return /^-?\d+$/.test(n) ? BigInt(n).toLocaleString("en-US") : "—";
	if (n == null || !Number.isFinite(n)) return "—";
	return Math.round(n).toLocaleString("en-US");
}
