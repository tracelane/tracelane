"use client";

import { type IdentityRef, identityHref } from "@/lib/kya/identity";
import type { KyaWindow } from "@/lib/kya/types";
import Link from "next/link";

/** One face across directory, profiles and trace surfaces. Assets are local. */
export function IdentityAvatar({
	identity,
	size = 24,
	link = true,
	showLabel = false,
	window,
}: {
	identity: IdentityRef;
	size?: 24 | 40 | 96;
	link?: boolean;
	showLabel?: boolean;
	window?: KyaWindow;
}) {
	const a = identity.avatar;
	const face = (
		<span
			role="img"
			aria-label={identity.label}
			className="inline-flex shrink-0 items-center justify-center rounded-card border border-line font-semibold"
			style={{
				width: size,
				height: size,
				fontSize: size * 0.42,
				color: `color-mix(in oklab, var(--ink) 70%, hsl(${a.hue} 60% 50%))`,
				background: `color-mix(in oklab, var(--surface) 92%, hsl(${a.hue} 60% 50%))`,
			}}
		>
			{a.kind === "motif" ? (
				<span
					aria-hidden="true"
					className="block bg-current"
					style={{
						width: "70%",
						height: "70%",
						maskImage: `url(/kya/glyphs/${a.glyph}.svg)`,
						maskRepeat: "no-repeat",
						maskSize: "contain",
						maskPosition: "center",
					}}
				/>
			) : a.kind === "mark" ? (
				<img
					src={a.src}
					width={size}
					height={size}
					alt=""
					className="h-3/4 w-3/4 object-contain"
				/>
			) : (
				<span aria-hidden="true">{a.letter}</span>
			)}
		</span>
	);
	const content = (
		<>
			{face}
			{showLabel && (
				<span className="min-w-0 break-words">{identity.label}</span>
			)}
		</>
	);
	return link && identity.kind !== "provider" ? (
		<Link
			href={`${identityHref(identity)}${window ? `?window=${window}` : ""}`}
			onClick={(event) => event.stopPropagation()}
			aria-label={`Open ${identity.label} profile`}
			title={`Open ${identity.label} profile`}
			className="inline-flex min-w-0 items-center gap-2 rounded-card text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-focus-ring"
		>
			{content}
		</Link>
	) : (
		<span className="inline-flex min-w-0 items-center gap-2">{content}</span>
	);
}
