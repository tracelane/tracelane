"use client";

import { reportClientError } from "@/lib/report-error";
import { useEffect } from "react";

/** Reports uncaught errors and unhandled promise rejections anywhere in the app. */
export function ErrorListener() {
	useEffect(() => {
		const onError = (e: ErrorEvent) =>
			reportClientError(e.error ?? e.message, "window");
		const onRejection = (e: PromiseRejectionEvent) =>
			reportClientError(e.reason, "rejection");
		window.addEventListener("error", onError);
		window.addEventListener("unhandledrejection", onRejection);
		return () => {
			window.removeEventListener("error", onError);
			window.removeEventListener("unhandledrejection", onRejection);
		};
	}, []);
	return null;
}
