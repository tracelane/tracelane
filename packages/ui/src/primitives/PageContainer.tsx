import type { HTMLAttributes } from "react";
export function PageContainer({
	className = "",
	...props
}: HTMLAttributes<HTMLElement>) {
	return (
		<main
			{...props}
			className={`page-container app-canvas min-w-0 flex-1 px-4 py-4 sm:px-6 lg:px-8 xl:px-10 ${className}`}
		/>
	);
}
