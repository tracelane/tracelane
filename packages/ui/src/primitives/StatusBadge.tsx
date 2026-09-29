import type { ReactNode } from "react";
import { Badge, type BadgeProps } from "./Badge";
const tones: Record<string, BadgeProps["tone"]> = {
	ok: "ok",
	completed: "ok",
	pass: "ok",
	passed: "ok",
	approved: "ok",
	enabled: "ok",
	sampling: "ok",
	closed: "ok",
	error: "danger",
	failed: "danger",
	fail: "danger",
	blocked: "danger",
	block: "danger",
	blocking: "danger",
	firing: "danger",
	open: "danger",
	pending: "warn",
	rotating: "warn",
	truncated: "warn",
	warned: "warn",
	warn: "warn",
	half_open: "warn",
	needs_review: "warn",
	not_judged: "warn",
	running: "info",
	revoked: "neutral",
	disabled: "neutral",
	not_configured: "neutral",
	expired: "warn",
};
const aliases: Record<string, string> = {
	success: "ok",
	successful: "ok",
	warning: "warned",
};
export function StatusBadge({
	status,
	label,
	detail,
	tone,
	title,
	className,
}: {
	status: string;
	label?: ReactNode;
	detail?: ReactNode;
	tone?: BadgeProps["tone"];
	title?: string;
	className?: string;
}) {
	const key = aliases[status.toLowerCase()] ?? status.toLowerCase();
	const words = key.replaceAll("_", " ");
	return (
		<Badge
			tone={tone ?? tones[key] ?? "neutral"}
			title={title}
			className={className}
		>
			{label ??
				(key === "ok" ? "OK" : words.charAt(0).toUpperCase() + words.slice(1))}
			{detail != null && <> · {detail}</>}
		</Badge>
	);
}
