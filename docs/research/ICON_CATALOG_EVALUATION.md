# Icon Catalog Evaluation

Status: Phase 2 research decision — 2026-08-18

## Decision

Use **Tabler Icons** as the default extended icon catalog for KDBX Fortress.

Initial pinned upstream baseline:

- Project: `tabler/tabler-icons`
- Release: `v3.46.0`
- Release commit: `8ac7d81b72ece11072ef25ea9fd92e80c6f3c9fc`
- License: MIT

KDBX Fortress must not depend on Tabler's live website or mutable `main` branch at runtime. The provider is versioned and replaceable so another catalog can be added or substituted later without changing the Vault Core.

## Why Tabler

Tabler is the best fit among the evaluated candidates because it combines:

- a very large, visually consistent SVG catalog,
- a simple permissive MIT license,
- compact 24×24 outline artwork suitable for Android UI,
- upstream names, categories, tags, and aliases that can support local search and automatic suggestions,
- stable tagged releases suitable for reproducible ingestion,
- straightforward redistribution and local caching when the MIT notice is preserved.

The public catalog contained more than 6,100 icons at the time of this evaluation. Exact catalog size is intentionally not treated as an application invariant; KDBX Fortress pins a provider version instead.

## Candidates evaluated

### Tabler Icons — selected

**Strengths**

- MIT license with simple redistribution obligations.
- Large and consistent general-purpose catalog.
- SVG source with predictable geometry and styling.
- Metadata supports names, categories, tags, and aliases.
- Tagged releases allow immutable version pinning.
- Good fit for folders, groups, entries, settings, storage, devices, security, finance, development, communication, and other common password-manager concepts.

**Tradeoffs**

- Primarily outline style; not every brand/service has a dedicated icon.
- Extended catalog must be mirrored/versioned carefully so runtime availability does not depend on an upstream website.

### Google Material Symbols — not selected as the extended catalog

**Strengths**

- Apache-2.0 licensed.
- Excellent Android/Material integration.
- Multiple visual axes/styles and Android-friendly distribution.

**Why not the primary catalog**

- Smaller general catalog than Tabler.
- Strong Material visual identity and font-centric distribution are less attractive for the planned searchable object-icon catalog.
- Still useful for Android/system UI where a native Material symbol is the clearer choice.

### Lucide — viable fallback, not selected

**Strengths**

- High-quality consistent SVG icon set.
- Permissive licensing.
- Strong ecosystem and active maintenance.

**Why not selected**

- Tabler currently offers the better combination of catalog breadth and rich searchable metadata for this specific use case.
- Lucide also carries Feather-derived MIT provenance alongside its ISC licensing, which is manageable but slightly more complex than the selected single-source Tabler path.

### Remix Icon — rejected for this architecture

Remix Icon is visually suitable, but its custom license contains attribution and redistribution restrictions beyond a simple permissive MIT/Apache model. Those conditions are unnecessary friction for a project-controlled, versioned, on-demand mirror/cache design. It is therefore not selected.

## Privacy architecture

The most important design rule is:

> **Vault-derived text is never sent to an icon provider.**

Folder names, group names, entry titles, usernames, URLs, notes, tags, custom fields, and search strings stay on-device.

### Local catalog index

At build/release time, KDBX Fortress generates a compact catalog index from the pinned Tabler release. The application may ship or update this metadata index independently of the full icon payload set.

The local index contains only non-secret provider metadata such as:

- provider ID,
- provider version,
- icon ID/name,
- category,
- tags,
- aliases,
- expected payload hash,
- optional baseline/offline classification.

Automatic matching and manual search run entirely against this local index.

### On-demand payload download

Only after local matching resolves an icon ID may the Android-side provider fetch the corresponding SVG payload.

A network request may therefore contain only non-secret catalog information such as:

- provider/version,
- icon ID,
- ordinary transport metadata inherent to the connection.

It must never contain the source entry/group/folder text that led to the suggestion.

## Distribution model

Do not make runtime search or payload availability depend directly on `tabler.io`, npm, unpkg, jsDelivr, GitHub `main`, or another mutable third-party endpoint.

Preferred model:

1. Pin an audited Tabler release.
2. Verify the release/tag identity in the ingestion pipeline.
3. Generate the local metadata/search manifest.
4. Normalize and validate allowed SVG payloads.
5. Calculate SHA-256 for every published icon payload.
6. Publish an immutable, versioned catalog snapshot from a KDBX Fortress-controlled static origin or release artifact.
7. Keep the original MIT license/copyright notice with the redistributed catalog.

Conceptual immutable path:

`/icons/tabler/v3.46.0/<icon-id>.svg`

Changing upstream versions must be an explicit catalog update, not a transparent mutation.

## Android-side module boundary

All icon networking and caching stay outside the Rust Vault Core.

Conceptually:

```text
Vault/UI model
    |
    | non-secret local display label
    v
Local IconCatalogIndex
    |
    | resolved icon ID only
    v
Android IconProvider
    |                  \
    v                   v
local cache        versioned remote catalog
```

The Vault Core remains fully offline and does not gain:

- HTTP/DNS dependencies,
- Internet permission,
- icon-download code,
- provider-specific APIs,
- telemetry.

A replaceable Android-side provider interface should separate local catalog search from remote payload retrieval.

## Search and suggestion behavior

Local search should normalize user-visible text and rank matches using, in order of relevance:

1. exact icon name/alias,
2. whole-token name/alias match,
3. tag match,
4. category match,
5. controlled prefix/fuzzy match.

Automatic suggestions may use folder/group/entry display names locally, but they are suggestions only. Manual selection always remains available.

Do not infer a sensitive semantic category remotely. For example, a group named after a medical condition, bank, employer, or private project must not cause that text to leave the device.

## Bundled baseline set

Bundle only a small curated subset from the same pinned Tabler version so the application remains useful offline from first launch.

The baseline should cover common concepts such as:

- folder/group,
- key/password/lock/shield,
- web/globe/link,
- user/identity,
- mail/chat/phone,
- card/bank/wallet,
- server/database/cloud/storage,
- Wi-Fi/network/router,
- code/terminal/Git,
- document/note/calendar,
- home/work/travel,
- settings/tools,
- generic application/site fallback.

The exact baseline membership is an implementation detail and may evolve independently of the full extended catalog.

## Offline behavior

- Bundled baseline icons are always available.
- Previously downloaded extended icons remain usable from cache.
- If an assigned extended icon is unavailable offline and not cached, show a deterministic generic/baseline fallback rather than a broken placeholder.
- Never require network access to open, browse, search, edit, or save the vault.

## Cache policy

Cache keys must include at least:

- provider,
- provider version,
- icon ID,
- expected SHA-256.

The cache must not persist the vault text or search query that caused an icon to be selected.

Provider upgrades must not silently reinterpret an existing icon ID. Existing assignments should retain their provider/version identity until explicitly migrated.

## Payload security

Downloaded SVG is untrusted input even when served from the project-controlled mirror.

Required controls:

- HTTPS only,
- immutable versioned paths,
- expected SHA-256 verification before use/cache,
- strict response-size limit,
- strict accepted media/content format,
- reject scripts, external references, remote resources, event handlers, and unsupported XML/SVG constructs,
- no XML external entities,
- sanitize/parse into a restricted vector representation before rendering where practical,
- fail safely to a baseline icon on validation errors.

## Licensing and notices

Tabler assets remain under their original MIT license; they are **not relicensed as AGPL-3.0-only** merely because KDBX Fortress code is AGPL-licensed.

Before bundling or mirroring Tabler assets, KDBX Fortress must:

- retain the Tabler copyright and MIT license notice,
- list the dependency/catalog in third-party notices,
- include the notice with any redistributed catalog snapshot where required,
- keep project branding rules separate from third-party icon licensing.

## Update policy

Catalog updates are deliberate dependency updates:

1. select a new stable upstream tag,
2. inspect license/provenance changes,
3. regenerate metadata and hashes,
4. validate the catalog,
5. review additions/removals/renames that affect existing mappings,
6. publish a new immutable provider version,
7. regression-test search, suggestions, caching, and offline fallback.

Do not delete old published provider versions while released KDBX Fortress versions can still reference them.

## Acceptance criteria for implementation

The later implementation is complete only when tests prove that:

- ordinary icon search and suggestions work without network access,
- no vault-derived search text reaches the network layer,
- the extended icon payload is fetched only by resolved provider/version/icon ID,
- corrupted or substituted SVG fails hash/validation checks,
- cached icons work offline,
- a cache miss offline falls back cleanly,
- provider-version changes do not mutate existing icon assignments,
- the Vault Core remains network-incapable,
- third-party license notices are shipped correctly.

## Result

**Selected:** Tabler Icons via a pinned, immutable, privacy-preserving, replaceable Android-side icon provider.

This fulfills the catalog-selection research task without committing KDBX Fortress to a live third-party service or expanding the Vault Core's attack surface.
