# KDBX Fortress Roadmap

## Phase 0 – Research, security foundations, and compatibility

- [x] Analyze OneKeePass/mobile as an additional research source: architecture, mobile/Android integration, KDBX handling, UX, security decisions, and solved edge cases. Derive and document lessons learned only; do not copy, port, or reuse source code.
  - Findings: [`docs/research/ONEKEEPASS_MOBILE_LESSONS.md`](docs/research/ONEKEEPASS_MOBILE_LESSONS.md)
  - Reviewed upstream snapshots: OneKeePass/mobile `ba14115a4f31cd26a68892824262edcbeea8bba3` and OneKeePass/onekeepass-core `7f1b6b2655d7f4c388bb100a2de3e9bbaf2b8fd5`.

## Phase 2 – Android application and UX

- [x] Research and select a free, legally suitable, high-quality and extensive icon source/catalog for folders, groups, entries, and other UI objects.
  - Selected: **Tabler Icons**, initially pinned to upstream `v3.46.0` / commit `8ac7d81b72ece11072ef25ea9fd92e80c6f3c9fc`, under the original MIT license.
  - Decision and implementation constraints: [`docs/research/ICON_CATALOG_EVALUATION.md`](docs/research/ICON_CATALOG_EVALUATION.md)
  - Bundle only a small essential baseline icon set with the application.
  - Do not bundle the full icon catalog with the application.
  - Provide the extended catalog online and fetch icons on demand through a dedicated, replaceable icon-provider module outside the Vault Core.
  - Keep the searchable icon metadata index local; folder/group/entry names and search strings must never be sent to the icon provider.
  - Resolve suggestions locally to provider/version/icon IDs and download only the resolved icon payload.
  - Use immutable versioned catalog snapshots and validate downloaded SVG payloads against expected hashes before caching/rendering.
  - The Rust/Vault Core must remain fully offline, have no Internet permission, and acquire no network dependency through icon handling.
  - Support fast icon search by names, tags, categories, and aliases.
  - Support automatic matching/suggestions from folder, group, and entry names while always allowing manual selection.
  - Cache previously fetched icons where appropriate and provide sensible offline fallback to the bundled baseline set.
  - Preserve third-party MIT notices and keep Tabler assets under their original license rather than treating them as AGPL-licensed project code.
