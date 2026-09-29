export function CaseInput({ value }: { value: unknown }) {
	const messages = Array.isArray(value) ? value : [];
	const lastUser = messages.findLastIndex(
		(m) => m && typeof m === "object" && m.role === "user",
	);
	const ordered =
		lastUser < 0
			? messages
			: [messages[lastUser], ...messages.filter((_, i) => i !== lastUser)];
	return (
		<div className="max-w-md space-y-3">
			{ordered.map((message, index) => {
				const content = message?.content;
				const text =
					typeof content === "string"
						? content
						: Array.isArray(content)
							? content
									.map((p) =>
										typeof p?.text === "string"
											? p.text
											: "[Non-text content — see Raw]",
									)
									.join("\n")
							: "[Non-text content — see Raw]";
				return (
					<div
						key={`${index}:${JSON.stringify(message)}`}
						data-testid="case-message"
					>
						<p className="text-xs font-semibold text-ink-2">
							{typeof message?.role === "string" ? message.role : "Message"}
						</p>
						<p className="whitespace-pre-wrap break-words text-sm">{text}</p>
					</div>
				);
			})}
			<details>
				<summary className="cursor-pointer text-xs text-ink-2">Raw</summary>
				<pre className="mt-2 whitespace-pre-wrap break-words text-xs">
					{JSON.stringify(value, null, 2)}
				</pre>
			</details>
		</div>
	);
}
