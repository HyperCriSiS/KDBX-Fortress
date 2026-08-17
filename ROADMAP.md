# KDBX Fortress Roadmap

## Phase 0 – Research, security foundations, and compatibility

- [x] Analyze OneKeePass/mobile as an additional research source: architecture, mobile/Android integration, KDBX handling, UX, security decisions, and solved edge cases. Derive and document lessons learned only; do not copy, port, or reuse source code.
  - Findings: [`docs/research/ONEKEEPASS_MOBILE_LESSONS.md`](docs/research/ONEKEEPASS_MOBILE_LESSONS.md)
  - Reviewed upstream snapshots: OneKeePass/mobile `ba14115a4f31cd26a68892824262edcbeea8bba3` and OneKeePass/onekeepass-core `7f1b6b2655d7f4c388bb100a2de3e9bbaf2b8fd5`.

## Phase 2 – Android application and UX

- [ ] Research and select a free, legally suitable, high-quality and extensive icon source/catalog for folders, groups, entries, and other UI objects.
  - Bundle only a small essential baseline icon set with the application.
  - Do not bundle the full icon catalog with the application.
  - Provide the extended catalog online and fetch icons on demand through a dedicated, replaceable icon-provider module outside the Vault Core.
  - The Rust/Vault Core must remain fully offline, have no Internet permission, and acquire no network dependency through icon handling.
  - Support fast icon search by names, tags, categories, and aliases.
  - Support automatic matching/suggestions from folder, group, and entry names while always allowing manual selection.
  - Evaluate catalog size, visual consistency, quality, Android suitability, API/download stability, and licensing terms for on-demand use and local caching.
  - Cache previously fetched icons where appropriate and provide sensible offline fallback to the bundled baseline set.
  - Do not send vault secrets or unnecessary entry data to the icon provider; matching/network requests must be designed with privacy minimization in mind.
