import type { WorkspaceGlanceResponse } from "@/lib/metrics/fetch";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { StorageCard } from "./StorageCard";

const storage: NonNullable<WorkspaceGlanceResponse["storage"]> = {
	state: "ok",
	compressed_bytes: 20_000_000,
	uncompressed_bytes: 100_000_000,
	index_bytes: 2_000_000,
	primary_index_bytes: 1_000_000,
	on_disk_bytes: 24_000_000,
	ratio: 5,
	tables: [{ name: "spans", on_disk_bytes: 18_000_000, rows: 1000 }],
	disk: { free: 500_000_000, total: 1_000_000_000 },
};

it("shows the measured self-host storage breakdown", () => {
	const html = renderToStaticMarkup(<StorageCard storage={storage} />);
	expect(html).toContain("Compressed");
	expect(html).toContain("Uncompressed");
	expect(html).toContain("Indexes");
	expect(html).toContain("5.0×");
	expect(html).toContain("spans");
});

it("prints the exact actionable grant when ClickHouse denies the read", () => {
	const html = renderToStaticMarkup(
		<StorageCard storage={{ ...storage, state: "denied" }} />,
	);
	expect(html).toContain(
		"GRANT SELECT ON system.parts, system.disks TO &lt;user&gt;",
	);
	expect(html).not.toContain("5.0×");
});
