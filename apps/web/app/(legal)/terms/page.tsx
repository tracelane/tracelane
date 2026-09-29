import LegalDocPage from "../legal/[doc]/page";

export const dynamic = "force-static";
export const metadata = { title: "Terms of Service" };

export default function Page() {
	return LegalDocPage({ params: Promise.resolve({ doc: "terms" }) });
}
