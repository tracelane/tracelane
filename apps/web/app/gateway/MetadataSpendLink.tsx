"use client";
import { useState } from "react";

export function MetadataSpendLink({ hrefTemplate }: { hrefTemplate: string }) {
	const [key, setKey] = useState("");
	return (
		<form
			onSubmit={(event) => {
				event.preventDefault();
				if (/^[A-Za-z0-9_.:-]{1,64}$/.test(key))
					window.location.assign(
						hrefTemplate.replace("__KEY__", encodeURIComponent(key)),
					);
			}}
			className="inline-flex items-center gap-1 text-xs"
		>
			<label htmlFor="spend-metadata-key">Metadata key</label>
			<input
				id="spend-metadata-key"
				value={key}
				onChange={(event) => setKey(event.target.value)}
				className="w-28 rounded-control border border-line bg-surface px-2 py-1"
				aria-describedby="spend-metadata-help"
			/>
			<button type="submit" className="text-action-ink underline">
				Group
			</button>
			<span id="spend-metadata-help" className="sr-only">
				Letters, numbers, underscore, period, colon, or hyphen; up to 64
				characters.
			</span>
		</form>
	);
}
