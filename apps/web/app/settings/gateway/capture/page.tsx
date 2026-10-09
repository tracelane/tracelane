import { ContentCapture } from "@/components/settings/ContentCapture";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Content capture — Settings" };

export default function Page() {
	return <ContentCapture />;
}
