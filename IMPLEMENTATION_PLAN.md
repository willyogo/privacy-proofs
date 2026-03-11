# Venice Attestation Verifier Plan

Last updated: March 11, 2026

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
| 4. Certificate validation | Completed | Added app, Intel PCK, and NVIDIA certificate-chain validation against pinned root fingerprints plus CRL parsing/fetch support. |
| 5. Full evidence verification | In progress | Intel quote signature verification and QE report-data binding are local now; NVIDIA raw-evidence verification and Intel collateral validation are still pending. |
| 6. Polish, docs, and release prep | In progress | Switched to explicit verify actions, added optional collateral input, code-split the verifier, added CI, and refreshed the docs. |

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
- Replaced parse-on-every-keystroke with an explicit verify flow and optional collateral bundle upload
- Added typed normalization, pinned certificate-chain validation, and local Intel quote signature validation
- Reworked the verdict so embedded claims are advisory only and unsupported crypto paths remain partial
- Added repo-local parser, verdict, and UI regression tests plus a GitHub Actions CI workflow
