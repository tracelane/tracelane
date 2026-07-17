import { type VariantProps, cva } from "class-variance-authority";
import { type ButtonHTMLAttributes, forwardRef } from "react";
import { cn } from "../lib/cn";

const button = cva(
	"inline-flex items-center justify-center gap-2 rounded-lg font-medium whitespace-nowrap transition-colors outline-none focus-visible:ring-2 focus-visible:ring-seal focus-visible:ring-offset-2 focus-visible:ring-offset-bg disabled:pointer-events-none disabled:opacity-50",
	{
		variants: {
			// `primary` is the rationed Lava CTA — highest-intent action only. The
			// `.cta-lava` component class (tokens.css) carries the gradient, white
			// label, and lava glow; `bg-accent` stays the solid-fill fallback.
			variant: {
				primary: "cta-lava",
				secondary: "border border-line bg-surface text-ink hover:bg-surface-2",
				ghost: "text-ink-2 hover:bg-surface-2 hover:text-ink",
				danger: "bg-danger text-danger-on hover:bg-danger/90",
			},
			size: {
				sm: "h-8 px-3 text-[12.5px]",
				md: "h-9 px-4 text-[13px]",
				lg: "h-10 px-5 text-sm",
			},
		},
		defaultVariants: { variant: "secondary", size: "md" },
	},
);

export interface ButtonProps
	extends ButtonHTMLAttributes<HTMLButtonElement>,
		VariantProps<typeof button> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
	({ className, variant, size, ...props }, ref) => (
		<button
			ref={ref}
			className={cn(button({ variant, size }), className)}
			{...props}
		/>
	),
);
Button.displayName = "Button";
