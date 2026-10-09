import type { WorkspaceGlanceResponse } from "@/lib/metrics/fetch";
import { fmtBytes, fmtCount } from "@/lib/metrics/format";

type Storage = NonNullable<WorkspaceGlanceResponse["storage"]>;
const metric = (name: string, value: number | null) => (
	<div className="rounded-control border border-line bg-surface px-3 py-2">
		<dt className="t-metric-label">{name}</dt>
		<dd className="mt-1 font-mono tabular-nums">{fmtBytes(value)}</dd>
	</div>
);

export function StorageCard({ storage }: { storage: Storage }) {
	return (
		<section
			aria-label="Self-host storage"
			className="space-y-3 rounded-card border border-line bg-surface-2 p-4"
		>
			<h3 className="t-card-title">Storage on this server</h3>
			{storage.state === "denied" ? (
				<p className="text-sm text-warn-ink">
					Storage sizes need read access to ClickHouse&apos;s{" "}
					<code>system.parts</code>. Grant it to the gateway&apos;s ClickHouse
					user:{" "}
					<code>
						GRANT SELECT ON system.parts, system.disks TO &lt;user&gt;
					</code>
					.
				</p>
			) : storage.state === "over_cap" ? (
				<p className="text-sm">This storage read exceeded its resource cap.</p>
			) : storage.state === "unavailable" ? (
				<p className="text-sm">
					Couldn&apos;t compute storage sizes. Try again later.
				</p>
			) : storage.tables.length === 0 && storage.on_disk_bytes === 0 ? (
				<p className="text-sm">No data stored yet.</p>
			) : (
				<>
					<dl className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
						{metric("Compressed", storage.compressed_bytes)}
						{metric("Uncompressed", storage.uncompressed_bytes)}
						{metric("Indexes", storage.index_bytes)}
						<div className="rounded-control border border-line bg-surface px-3 py-2">
							<dt className="t-metric-label">Data compression ratio</dt>
							<dd className="mt-1 font-mono tabular-nums">
								{storage.ratio === null ? "—" : `${storage.ratio.toFixed(1)}×`}
							</dd>
						</div>
					</dl>
					<p className="text-xs text-ink-2">
						{fmtBytes(storage.on_disk_bytes)} in active table parts ·{" "}
						{fmtBytes(storage.primary_index_bytes)} primary indexes. Disk free{" "}
						{fmtBytes(storage.disk?.free)} of {fmtBytes(storage.disk?.total)}.
					</p>
					{storage.tables.length > 0 && (
						<details className="text-xs">
							<summary className="cursor-pointer">
								Top tables ({storage.tables.length})
							</summary>
							<ul className="mt-2 space-y-1">
								{storage.tables.map((table) => (
									<li key={table.name} className="flex justify-between gap-3">
										<span className="font-mono">{table.name}</span>
										<span className="font-mono tabular-nums">
											{fmtBytes(table.on_disk_bytes)} · {fmtCount(table.rows)}{" "}
											rows
										</span>
									</li>
								))}
							</ul>
						</details>
					)}
					<p className="text-xs text-ink-3">
						Active ClickHouse table parts only. Disk use also includes logs,
						temporary files and other databases.
					</p>
				</>
			)}
		</section>
	);
}
