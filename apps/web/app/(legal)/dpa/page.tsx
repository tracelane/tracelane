import LegalDocPage from "../legal/[doc]/page";

export const dynamic = "force-static";
export const metadata = { title: "Data Processing Addendum" };

export default function Page() {
	return LegalDocPage({ params: Promise.resolve({ doc: "dpa" }) });
}
