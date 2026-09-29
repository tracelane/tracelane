import { SessionTranscript } from "@/components/sessions/SessionTranscript";
import { CopySessionLink } from "@/components/sessions/TurnActions";
import { requireSession } from "@/lib/auth";
import { GatewayError } from "@/lib/gateway";
import { getListPageSettings } from "@/lib/list-page-settings";
import { fetchSessionTranscript } from "@/lib/sessions";
import { PageHeader } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
interface Props {
	params: Promise<{ sessionId: string }>;
	searchParams?: Promise<{ cursor?: string }>;
}
export async function generateMetadata({ params }: Props): Promise<Metadata> {
	const { sessionId } = await params;
	return { title: `Session ${sessionId.slice(0, 16)} — Tracelane` };
}
export const dynamic = "force-dynamic";
export default async function SessionDetailPage({
	params,
	searchParams,
}: Props) {
	const { sessionId } = await params;
	const cursor = (await searchParams)?.cursor;
	const session = await requireSession();
	const settings = await getListPageSettings();
	let data: Awaited<ReturnType<typeof fetchSessionTranscript>>;
	try {
		data = await fetchSessionTranscript(sessionId, {
			limit: settings.sizes.session_turns,
			cursor,
		});
	} catch (error) {
		if (error instanceof GatewayError && error.status === 403)
			return (
				<div className="p-6">
					<p role="alert">
						Access denied. Your credentials need permission to read sessions.
					</p>
				</div>
			);
		throw error;
	}
	if (data === null) notFound();
	return (
		<div className="mx-auto max-w-7xl p-6">
			<PageHeader
				title={sessionId}
				breadcrumb={
					<Link className="text-sm underline" href="/sessions">
						← Sessions
					</Link>
				}
				actions={<CopySessionLink sessionId={sessionId} />}
			/>

			<SessionTranscript
				data={data}
				sessionId={sessionId}
				viewerRole={session.role}
				userId={session.userId}
			/>
			<nav aria-label="Session turns" className="mt-4 flex gap-4 text-sm">
				{cursor && (
					<Link
						className="underline"
						href={`/sessions/${encodeURIComponent(sessionId)}`}
					>
						First page
					</Link>
				)}
				{data.next_cursor && (
					<Link
						className="underline"
						href={`/sessions/${encodeURIComponent(sessionId)}?cursor=${encodeURIComponent(data.next_cursor)}`}
					>
						Show next {settings.sizes.session_turns} turns
					</Link>
				)}
			</nav>
		</div>
	);
}
