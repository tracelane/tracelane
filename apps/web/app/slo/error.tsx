"use client";

import { SegmentError } from "@/components/error-boundary/SegmentError";

export default function SloError(props: {
	error: Error & { digest?: string };
	reset: () => void;
}) {
	return <SegmentError {...props} />;
}
