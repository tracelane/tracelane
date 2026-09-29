import { ReadFailure } from "@/components/empty-states/ReadFailure";
import { FailoverManager } from "@/components/settings/FailoverManager";
import { ModelAliasManager } from "@/components/settings/ModelAliasManager";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import {
	type GatewaySettings,
	GatewaySettingsView,
} from "./GatewaySettingsView";
export default async function GatewaySettingsPage() {
	try {
		const data = await gatewayGet<GatewaySettings>("/v1/gateway/settings");
		return (
			<GatewaySettingsView
				data={data}
				aliasManager={<ModelAliasManager />}
				failoverManager={
					<FailoverManager
						operatorChain={data.failover.chain.map((h) => h.model)}
					/>
				}
			/>
		);
	} catch (err) {
		return (
			<ReadFailure
				status={err instanceof GatewayError ? err.status : 503}
				resource="gateway settings"
				retryHref="/settings/gateway"
			/>
		);
	}
}
