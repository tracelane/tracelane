import { type VariantProps, cva } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

const badge = cva(
	"inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold tabular-nums",
	{
		variants: {
			// status tones pair with an icon/shape at the call site — never colour alone.
			tone: {
				neutral: "bg-surface-2 text-ink-2",
				ok: "bg-ok-soft text-ok",
				danger: "bg-danger-soft text-danger",
				warn: "bg-warn-soft text-warn",
				info: "bg-info-soft text-info",
				seal: "bg-seal-soft text-seal-ink", // provenance chip
				accent: "bg-accent-soft text-accent-ink", // active / function
			},
		},
		defaultVariants: { tone: "neutral" },
	},
);

export interface BadgeProps
	extends HTMLAttributes<HTMLSpanElement>,
		VariantProps<typeof badge> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
	return <span className={cn(badge({ tone }), className)} {...props} />;
}
