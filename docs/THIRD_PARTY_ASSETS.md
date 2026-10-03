# Self-hosted browser assets

The dependency credits and collected upstream license texts are listed in
[Third party notices](../THIRD_PARTY_NOTICES.md). Browser licenses are also
included under `server/static/vendor/licenses`, and font licenses beside the
font assets, so the server image preserves these notices.

Warden does not fetch JavaScript, CSS, or fonts from a public CDN at runtime.
The application serves these files from `server/static` under its own origin:

- Alpine.js 3.17.4 CSP build: `static/vendor/alpinejs.min.js`  
  MIT; SHA-256 `50B8777905342F552BC7F8833321AC95D49244EFF2CAD1DFE7F48376F98131CE`; license: `LICENSES/Alpine.js-MIT.txt`
- Chart.js 4.4.4: `static/vendor/chart.min.js`  
  MIT; SHA-256 `282C084E6709689B1F49FAAA84E99D22CC0331F25001743ADA1F72C9E7C56389`; license: `LICENSES/Chart.js-MIT.txt`
- HTMX 1.9.12: `static/vendor/htmx.min.js`  
  BSD-2-Clause; SHA-256 `449317ADE7881E949510DB614991E195C3A099C4C791C24DACEC55F9F4A2A452`; license: `LICENSES/HTMX-BSD-2-Clause.txt`
- Inter font: `static/fonts/inter`  
  SIL Open Font License 1.1; license: `LICENSES/Inter-OFL-1.1.txt`
- JetBrains Mono font: `static/fonts/jetbrains-mono`  
  SIL Open Font License 1.1; license: `LICENSES/JetBrains-Mono-OFL-1.1.txt`
- Compiled Tailwind and application CSS: `static/css`

The server image compiles Tailwind during the build. The browser receives only
the generated local stylesheet. Alpine and fonts are vendored so image builds
cannot silently replace the reviewed runtime libraries with a newer package.

For an update, verify the upstream release and license, scan the dependency,
replace the vendored file, record its version and SHA-256 hash in the release
evidence, run the complete test suite, and review the CSP before deployment.
The frontend contract test fails if a template or stylesheet introduces a
remote script, stylesheet, font import, or CSS asset URL.
