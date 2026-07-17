import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge Tailwind class names with conflict resolution.
 * `cn("px-2", cond && "px-4")` → later wins, deduped. Used by every primitive.
 */
export function cn(...inputs: ClassValue[]): string {
	return twMerge(clsx(inputs));
}
