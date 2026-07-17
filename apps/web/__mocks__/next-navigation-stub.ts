/** Stub for next/navigation — used by vitest node-env tests that renderToStaticMarkup
 * client components. The real hooks throw without a router context; these stubs
 * return safe no-op values so the unit tests can render the component tree. */
export const useRouter = () => ({
	push: (_url: string) => {},
	replace: (_url: string) => {},
	prefetch: (_url: string) => {},
	back: () => {},
	forward: () => {},
	refresh: () => {},
});
export const usePathname = () => "";
export const useSearchParams = () => new URLSearchParams();
export const useParams = () => ({});
export const redirect = (_url: string): never => {
	throw new Error(`redirect: ${_url}`);
};
export const notFound = (): never => {
	throw new Error("not_found");
};
