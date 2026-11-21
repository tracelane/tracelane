"use client";

import dynamic from "next/dynamic";

/** The export control is loaded on demand, so it is absent from every other page's bundle. */
export const ConfigExportLazy = dynamic(
	() => import("./ConfigExport").then((m) => m.ConfigExport),
	{ ssr: false },
);
