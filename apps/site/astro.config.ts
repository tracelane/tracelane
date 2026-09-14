import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import tailwindcss from "@tailwindcss/vite";

// https://astro.build/config
export default defineConfig({
  site: "https://tracelane.dev",
  integrations: [sitemap()],
  vite: {
    plugins: [tailwindcss()],
    build: {
      // THE SITE'S BROWSER-SUPPORT FLOOR, PINNED — and it had to become explicit
      // here rather than inherited. Vite's `baseline-widely-available` default is a
      // MOVING target: Vite 7.3.6 resolved it to chrome107/edge107/firefox104/
      // safari16, Vite 8.3.0 (which Astro 7 brings) resolves it to chrome111/
      // edge111/firefox114/safari16.4/ios16.4. Safari 16.4 is the version that gained
      // Media Queries Level 4 range syntax, so on the new baseline Lightning CSS stops
      // lowering it: measured on this build, all 22 `@media(min-width:…)` became
      // `@media (width>=…)`, and a browser below the floor does not fall back — it
      // drops the whole query, so every responsive rule on tracelane.dev would stop
      // applying at once on iOS 16.0–16.3.
      //
      // These four values ARE Vite 7's baseline, i.e. exactly what prod serves today.
      // Pinning them keeps the 6->7 bump (B-373, an AVIF-decoder RCE) a pure security
      // change. Raising the floor is a real decision about who we drop, and it gets
      // made on its own, not as a side effect of patching an advisory.
      cssTarget: ["chrome107", "edge107", "firefox104", "safari16"],
    },
  },
  // Astro 7 changed the default to `"jsx"`, which drops the whitespace BETWEEN
  // inline elements the way React does. Measured on this site's own build, not
  // assumed: it glues real copy together — "licensed underApache 2.0", "The/spec
  // directory", "5months", "14MB", "✓Apache 2.0", "provenPLT-23" — across the
  // changelog, the comparison table, the homepage footnotes and /terms.
  // `true` is v6's behaviour, so the 6->7 bump (B-373, an AVIF-decoder RCE) ships
  // as a pure security change with a byte-identical rendered text stream. Adopting
  // JSX whitespace is a separate, deliberate edit to the copy — not a side effect
  // of patching an advisory.
  compressHTML: true,
  build: {
    inlineStylesheets: "auto",
  },
  prefetch: {
    defaultStrategy: "viewport",
  },
});
