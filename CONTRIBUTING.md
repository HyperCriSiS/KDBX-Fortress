# Contributing to KDBX Bastion

KDBX Bastion welcomes contributions, but password-manager code has a high security and data-integrity impact. Changes are therefore expected to be small, reviewable, test-backed, and consistent with the documented trust boundaries.

## Before changing code

Read at least:

- `Roadmap.md`
- `ARCHITECTURE.md`
- `MODULE_BOUNDARIES.md`
- `SECURITY_INVARIANTS.md`
- `THREAT_MODEL.md`
- `TEST_STRATEGY.md`

For Autofill/Credential Manager changes also read:

- `ANDROID_CREDENTIAL_ARCHITECTURE.md`
- `LESSONS_FROM_EXISTING_CLIENTS.md`
- `ISSUE_PR_CLASSIFICATION.md`

## Development principles

- Reproduce bugs before fixing them where feasible.
- Add a regression test for reliability/security bugs when technically representable.
- Do not weaken target verification to make one app/browser work silently.
- Do not add network access outside approved sync modules/build variants.
- Do not make normal credential Fill mutate the vault.
- Do not log or persist plaintext secrets for debugging.
- Keep platform/OEM workarounds inside platform adapters.
- Avoid unrelated refactors in bug-fix pull requests.
- Do not introduce new cryptographic primitives.

## Security-sensitive changes

Changes involving any of the following require explicit threat/invariant review:

- KDBX parsing/serialization;
- cryptography/KDFs;
- Android Keystore/biometrics;
- credential target identity;
- Autofill/Credential Manager secret release;
- exported Android components;
- sync/network capability;
- secret-memory/transport handling;
- plugin/extension capabilities.

The pull request should name the affected `SI-*` security invariants and describe negative/adversarial tests.

## Code provenance

Do not paste code from another project without checking its license and preserving all required copyright, license, and provenance notices.

If a contribution is an independent reimplementation informed by public behavior/issues, say so when provenance might otherwise be ambiguous.

## Developer Certificate of Origin

Contributions should use a `Signed-off-by` line to certify the Developer Certificate of Origin (DCO) process:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Git can add this with:

```bash
git commit -s
```

This keeps contribution provenance explicit without requiring a broad copyright-assignment CLA.

## Pull requests

A good pull request should contain:

- the problem/root cause;
- the smallest reasonable change;
- tests added/updated;
- security implications;
- affected platforms/API levels;
- relevant issue(s);
- documentation changes if behavior or architecture changed.

A successful build alone is not sufficient evidence that an Autofill/security/data-integrity change is correct.
