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
| 2. Input normalization and schema validation | Completed | Added nested payload normalization, structural error handling, and browser-side verdict generation. |
| 3. Deterministic local checks | Completed | Added nonce, public key, address, quote report-data, quote measurement, event-log, and embedded-claim consistency checks. |
| 4. Certificate validation | Pending | Parse cert chains and validate against pinned trust anchors. |
| 5. Full evidence verification | Pending | Verify NVIDIA evidence and Intel TDX quote locally. |
| 6. Polish, docs, and release prep | Pending | Explain failures clearly, add docs, and harden the UX. |

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
- Added sample-report coverage to prove the provided attestation verifies and a tampered nonce fails
