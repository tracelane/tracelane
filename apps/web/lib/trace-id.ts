/** Stored trace references may be UUIDs or 16-byte OTLP hexadecimal IDs. */
export function isTraceId(value: unknown): value is string {
	return (
		typeof value === "string" &&
		(value.length === 32 || value.length === 36) &&
		/^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$/i.test(
			value,
		)
	);
}
