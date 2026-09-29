"use client";
import { PageHeader } from "@tracelanedev/ui";
import { usePathname } from "next/navigation";
import { SETTINGS_ITEMS, activeSettingsHref } from "./settings-nav-config";
export function SettingsPageHeader() {
	const active = activeSettingsHref(usePathname());
	return (
		<PageHeader
			title={
				SETTINGS_ITEMS.find((item) => item.href === active)?.label ?? "Settings"
			}
		/>
	);
}
