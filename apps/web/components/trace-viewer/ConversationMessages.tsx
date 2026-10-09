import { StatusBadge } from "@tracelanedev/ui";

function Message({ value }: { value: unknown }) {
	if (typeof value === "string")
		return <p className="whitespace-pre-wrap break-words">{value}</p>;
	if (!value || typeof value !== "object") return null;
	const message = value as Record<string, unknown>;
	const content = message.content ?? message.parts;
	const text =
		typeof content === "string"
			? content
			: Array.isArray(content)
				? content
						.map((part) =>
							typeof part === "object" && part !== null && "text" in part
								? String(part.text)
								: "[Non-text content — open trace]",
						)
						.join("\n")
				: "[Non-text content — open trace]";
	return (
		<div className="space-y-1">
			<p className="text-xs font-semibold uppercase text-ink-2">
				{typeof message.role === "string" ? message.role : "Message"}
			</p>
			<p className="whitespace-pre-wrap break-words">{text}</p>
			{text.includes("…[truncated]") && (
				<StatusBadge status="truncated when recorded" tone="warn" />
			)}
		</div>
	);
}

/** Shared role-labelled renderer for session turns and a selected trace span. */
export function ConversationMessages({ value }: { value: unknown }) {
	const values = Array.isArray(value) ? value : [value];
	return (
		<div className="space-y-4">
			{values.map((message, index) => (
				<Message key={`${index}:${JSON.stringify(message)}`} value={message} />
			))}
		</div>
	);
}
