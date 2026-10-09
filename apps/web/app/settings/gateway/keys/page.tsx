import { KeyPolicyManager } from "@/components/gateway/KeyPolicyManager";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Key policy — Settings" };

export default function Page() {
	return <KeyPolicyManager />;
}
