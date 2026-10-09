import { LimitsBudgets } from "@/components/gateway/LimitsBudgets";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Limits & budgets — Settings" };

export default function Page() {
	return <LimitsBudgets />;
}
