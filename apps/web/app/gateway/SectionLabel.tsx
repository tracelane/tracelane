/**
 * SectionLabel — the /gateway section divider: eyebrow type, a trailing hairline
 * rule, and an optional right-aligned control that belongs to the section.
 *
 * WHY IT IS A FILE AND NOT AN INLINE `<h2>`. The gateway surface has four data
 * sections and TWO of them live in different modules (`page.tsx` and
 * `SpendAttribution.tsx`), so an inline heading would be two definitions of "what
 * a section label looks like" on one screen — the same divergence the `Table` and
 * `SegmentedControl` primitives were extracted to end. It is deliberately scoped
 * to this route: `apps/web/app/dashboard/page.tsx` carries an equivalent private
 * helper, and promoting the two into `@tracelanedev/ui` is the right end state,
 * but a shared primitive is not something to edit while other work is in flight.
 *
 * The type itself is `.t-eyebrow` (12px / 600 / 0.10em uppercase / `--ink-2`), so
 * the grammar is tuned in tokens.css rather than here.
 */

import type { ReactNode } from "react";

export function SectionLabel({
	children,
	action,
}: {
	children: ReactNode;
	/** Right-aligned control owned by the section (e.g. a `SegmentedControl`). */
	action?: ReactNode;
}) {
	return (
		<div className="flex flex-wrap items-center gap-3">
			<h2 className="t-eyebrow">{children}</h2>
			{/* The rule takes whatever the label and the action leave, so the divider
			    is one continuous line at every width — and `min-w-8` keeps a visible
			    stub of it when a long label and a control squeeze the row on a phone
			    instead of collapsing it to zero and looking like a rendering fault. */}
			<span className="h-px min-w-8 flex-1 bg-line" />
			{action}
		</div>
	);
}
