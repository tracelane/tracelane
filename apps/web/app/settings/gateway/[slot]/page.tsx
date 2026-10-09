import { SlotView } from "@/components/gateway/SlotView";
import { GATEWAY_SLOTS } from "@/lib/gateway-controls";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

export const metadata: Metadata = { title: "Gateway — Settings" };

export default async function Page({
	params,
}: { params: Promise<{ slot: string }> }) {
	const { slot } = await params;
	const found = GATEWAY_SLOTS.find((s) => s.id === slot);
	if (!found) notFound();
	return <SlotView slot={{ ...found }} />;
}
