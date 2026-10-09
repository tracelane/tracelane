import { ProjectsManager } from "@/components/gateway/ProjectsManager";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Projects — Settings" };

export default function Page() {
	return <ProjectsManager />;
}
