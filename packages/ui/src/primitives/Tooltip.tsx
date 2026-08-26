"use client";

import {
	type ReactNode,
	useCallback,
	useEffect,
	useId,
	useRef,
	useState,
} from "react";
import { cn } from "../lib/cn";

/**
 * Hover/focus detail, as a primitive.
 *
 * **Why this exists.** Before it, the repo had NO tooltip or popover of any
 * kind — the only hover detail anywhere in the product was the native `title=`
 * attribute. `title` is the wrong tool for a data product three ways: it waits
 * ~1s before appearing, it cannot be styled (so a truncated hash renders in the
 * OS's font on the OS's yellow), and it is **invisible on touch**, which means
 * every detail behind one was unreachable on a tablet. Founder, 2026-08-19:
 * *"none hovering to see details are present"*.
 *
 * ## What it does that `title` cannot
 *
 * - **Opens on hover AND on keyboard focus**, so the detail is reachable without
 *   a pointer. `aria-describedby` links it to the trigger, so a screen reader
 *   announces it rather than it being a purely visual affordance.
 * - **Escape dismisses**, and dismissal is immediate — a tooltip you cannot get
 *   rid of is worse than none when it covers the row you are reading.
 * - **Flips when it would leave the viewport.** Measured against the real rect
 *   rather than assumed: a right-edge tooltip on the last column is the common
 *   case in a table, and one that renders off-screen is the same as no tooltip.
 * - **No new dependency.** ADR-074 §9 bans them; this is ~120 lines of platform.
 *
 * ## Deliberately NOT a click-popover
 *
 * This shows detail that is already true — a full hash, an exact timestamp, an
 * unrounded cost. It never contains an action, so it never needs to trap focus
 * or hold state. A thing with buttons in it is a Popover and is a different
 * component with different rules.
 */
export interface TooltipProps {
	/** The detail. Kept short — this is a glance, not a panel. */
	content: ReactNode;
	children: ReactNode;
	/** Preferred side; flips automatically when it would overflow. */
	side?: "top" | "bottom";
	/**
	 * Hover open delay. Focus is always instant — a keyboard user has already
	 * expressed intent, so making them wait is pure friction.
	 */
	delayMs?: number;
	className?: string;
}

export function Tooltip({
	content,
	children,
	side = "top",
	delayMs = 260,
	className,
}: TooltipProps) {
	const id = useId();
	const [open, setOpen] = useState(false);
	const [pos, setPos] = useState<{
		x: number;
		y: number;
		flip: boolean;
	} | null>(null);
	const anchorRef = useRef<HTMLSpanElement | null>(null);
	const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

	const clear = useCallback(() => {
		if (timer.current) {
			clearTimeout(timer.current);
			timer.current = null;
		}
	}, []);

	const place = useCallback(() => {
		const el = anchorRef.current;
		if (!el) return;
		const r = el.getBoundingClientRect();
		// Flip when the preferred side has no room. 44px is the tooltip's own
		// approximate height plus its offset — measured intent, not a guess at
		// whether it "probably fits".
		const wantsTop = side === "top";
		const noRoomTop = r.top < 44;
		const noRoomBottom = window.innerHeight - r.bottom < 44;
		// Flip when the PREFERRED side has no room — that is the whole rule.
		const flip = wantsTop ? noRoomTop : noRoomBottom;
		const onTop = wantsTop ? !flip : flip;
		setPos({
			x: r.left + r.width / 2,
			y: onTop ? r.top - 8 : r.bottom + 8,
			flip: !onTop,
		});
	}, [side]);

	const show = useCallback(
		(instant: boolean) => {
			clear();
			const run = () => {
				place();
				setOpen(true);
			};
			if (instant) run();
			else timer.current = setTimeout(run, delayMs);
		},
		[clear, delayMs, place],
	);

	const hide = useCallback(() => {
		clear();
		setOpen(false);
	}, [clear]);

	useEffect(() => () => clear(), [clear]);

	// A tooltip anchored to a rect must die when the rect moves, or it points at
	// nothing. Scroll and resize both move it; re-placing on scroll would fight
	// the scroll, so it dismisses instead.
	useEffect(() => {
		if (!open) return;
		const onKey = (e: KeyboardEvent) => {
			if (e.key === "Escape") hide();
		};
		window.addEventListener("keydown", onKey);
		window.addEventListener("scroll", hide, true);
		window.addEventListener("resize", hide);
		return () => {
			window.removeEventListener("keydown", onKey);
			window.removeEventListener("scroll", hide, true);
			window.removeEventListener("resize", hide);
		};
	}, [open, hide]);

	return (
		<>
			<span
				ref={anchorRef}
				aria-describedby={open ? id : undefined}
				onMouseEnter={() => show(false)}
				onMouseLeave={hide}
				onFocus={() => show(true)}
				onBlur={hide}
				className={cn("inline-flex max-w-full items-center", className)}
			>
				{children}
			</span>
			{open && pos && (
				<span
					role="tooltip"
					id={id}
					// `fixed` + the measured rect, so the tooltip is never clipped by
					// an ancestor's `overflow: hidden` — which every scrollable table
					// has, and which is why an absolutely-positioned tooltip
					// disappears inside one.
					style={{
						position: "fixed",
						left: pos.x,
						top: pos.y,
						transform: `translate(-50%, ${pos.flip ? "0" : "-100%"})`,
						zIndex: 60,
					}}
					// `border border-ink-inverse/15` (2026-08-22 contrast audit). `.tl-tooltip`
					// paints `--surface-inverse`, which is the deliberate dark layer in light
					// theme (17.32:1 against the canvas — a clear layer above the page) but is
					// #0d0e10 in DARK: byte-identical to `--bg`. There the tooltip measured
					// 1.00:1 against the canvas and 1.07:1 against a card, and neither of its
					// other two edge cues survives — `--shadow-overlay` is a black drop that
					// tokens.css itself says a near-black ground swallows, and the class carries
					// no hairline. A multi-line tooltip therefore floated as unboxed text over
					// the page. `border-ink-inverse/15` composites to ~#37373a / ~#303132 over
					// the tooltip in the two themes — one expression, an edge in both. The
					// StatCard hint tooltip already carried a hairline; the shared primitive,
					// which is the one most surfaces use, did not.
					className="tl-tooltip pointer-events-none max-w-xs rounded-lg border border-ink-inverse/15 px-2.5 py-1.5 text-xs leading-snug"
				>
					{content}
				</span>
			)}
		</>
	);
}
