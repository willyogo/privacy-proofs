# Venice Attestation Verifier Plan

Last updated: March 12, 2026

## Goal

Build a simple, open source, frontend-only app where users can paste or upload a Venice attestation report and immediately understand whether the report is valid, invalid, or only partially verified.

## Stack

- Vite
- React
- TypeScript
- Vitest
- `zod`
- `viem`
- `@noble/secp256k1`
- `@noble/hashes`
- `@peculiar/x509`

## Milestones

| Milestone | Status | Notes |
| --- | --- | --- |
| 1. App shell and UX scaffold | Completed | Built the one-page app, input flow, diagnostics panels, and Venice-inspired visual system. Verified with `npm test` and `npm run build` on March 11, 2026. |
| 2. Input normalization and schema validation | Completed | Replaced the loose record parser with typed `zod` normalization and explicit schema-path failures. |
| 3. Deterministic local checks | Completed | Added nonce, public key, address, quote report-data, quote measurement, event-log, and key-provider consistency checks. |
| 4. Certificate validation | Completed | Added app, Intel PCK, and NVIDIA certificate-chain validation against pinned trust roots for raw-report-only verification. |
| 5. Full evidence verification | Completed | Added Intel quote-cryptography verification, NVIDIA raw-evidence signature verification, and verdict rules that only promote to `Verified` on independent local crypto. |
| 6. Polish, docs, and release prep | In progress | Switched to explicit verify actions, simplified the app to raw-report-only input, code-split the verifier, added CI, refreshed the docs, and committed repo-local protocol fixtures; a single end-to-end `Verified` Venice golden report is still pending. |

## Repo Layout Target

```text
/Users/willy/Documents/GitHub/Venice/Privacy Proofs
  public/
  src/
    components/
    lib/
  tests/
```

## Milestone 1 Deliverables

- Vite + React + TypeScript scaffold
- Venice-inspired landing page and visual system
- Paste and upload JSON input flow
- Parsed report summary and diagnostics cards
- Clear verification verdict states: verified, partially verified, and failed
- Basic parser tests

## Completed Work Log

### March 11, 2026

- Created the initial frontend app scaffold with Vite, React, and TypeScript
- Added a tracked implementation plan file for milestone status updates
- Brought over the shared marble background, favicon, and Venice logomark
- Implemented paste and upload flows with early parse diagnostics
- Added initial normalization logic for nested `nvidia_payload`
- Added parser-focused Vitest coverage
- Verified the milestone with `npm test` and `npm run build`
- Promoted the placeholder card into an active verification engine with explicit verdicts
- Added browser-side checks for signing key/address binding, nonce binding, TDX quote report data, TDX measurements, event-log consistency, and embedded TDX or NVIDIA verification claims
- Replaced parse-on-every-keystroke with an explicit verify flow
- Added typed normalization, pinned certificate-chain validation, and local Intel quote signature validation
- Reworked the verdict so embedded claims are advisory only and unsupported crypto paths remain partial
- Added repo-local parser, verdict, and UI regression tests plus a GitHub Actions CI workflow

### March 12, 2026

- Added NVIDIA raw-evidence parsing, signature verification, nonce binding, architecture binding, and FWID binding
- Hardened certificate-chain validation so unordered PEM bundles still build from the actual leaf certificate
- Expanded the Intel trust store to accept the current SGX root used by the official QVL sample chain
- Added repo-local Intel and NVIDIA protocol fixtures plus regression tests for signature failures and raw-report-only verification behavior
- Documented that Intel's published QVL `sampleData/tdx` QE identity and `quote.dat` do not agree on QE `mrsigner`, so that fixture remains a regression sample rather than a full-positive golden
- Refocused the product on raw-report-only verification, removed collateral input and network fetch behavior, and downgraded embedded Venice or NRAS fields to provenance-only signals
