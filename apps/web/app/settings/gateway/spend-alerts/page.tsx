import { SpendAlerts } from "@/components/gateway/SpendAlerts";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Spend alerts — Settings" };

export default function Page() {
	return <SpendAlerts />;
}
