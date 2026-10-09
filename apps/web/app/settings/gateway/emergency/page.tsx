import { EmergencyControls } from "@/components/gateway/EmergencyControls";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Emergency controls — Settings" };

export default function Page() {
	return <EmergencyControls />;
}
