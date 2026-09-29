import LegalDocPage from "../legal/[doc]/page";

export const dynamic = "force-static";
export const metadata = { title: "Privacy Policy" };

export default function Page() {
	return LegalDocPage({ params: Promise.resolve({ doc: "privacy" }) });
}
