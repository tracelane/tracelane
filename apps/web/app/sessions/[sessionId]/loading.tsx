import { Skeleton } from "@tracelanedev/ui";
export default function Loading() {
	return (
		<div className="space-y-4 p-6" aria-label="Loading session transcript">
			<Skeleton className="h-12 w-1/2" />
			<Skeleton className="h-40 w-full" />
			<Skeleton className="h-40 w-full" />
		</div>
	);
}
