# Venice Attestation Verifier

`Venice Attestation Verifier` is a frontend-only app for inspecting a Venice attestation report in the browser and turning it into a concrete verification verdict.

You can paste raw JSON or upload a report file, and the app will:

- parse and normalize the report with explicit schemas
- validate local bindings, certificate chains, Intel TDX quote cryptography, and NVIDIA raw evidence in the browser
- treat embedded `verified`, `server_verification`, and `verifiedAt` fields as advisory provenance only
- show a verdict of `Verified`, `Partially verified`, or `Verification failed`

## Purpose

This repo exists to make Venice attestation reports easier to inspect without sending the report to a backend service. The current build performs real local validation for report structure, internal bindings, certificate chains, Intel TDX quote cryptography, and NVIDIA evidence signatures using only the raw report bytes Venice exposes.

Today, the app is best understood as a transparent verifier UI with an independent local verification engine that refuses to upgrade embedded Venice or NRAS claims into proof on their own.

## How It Works

The app is a Vite + React + TypeScript single-page application.

### Runtime flow

1. The user pastes JSON into the textarea or uploads a report file.
2. The user clicks `Verify report`.
3. `src/app.tsx` passes the raw report to `parseReportSource(...)` in `src/lib/normalize.ts`.
4. The parser:
   - validates that the report is JSON
   - validates the report against explicit `zod` schemas
   - normalizes `nvidia_payload` when it arrives as a JSON string
   - records precise schema-path failures when parsing fails
5. `parseReportSource(...)` lazy-loads `verifyNormalizedReport(...)` from `src/lib/verifier.ts`.
6. The verifier runs local checks, including:
   - signing public key -> Ethereum address derivation
   - equality checks across duplicated signing key fields
   - nonce consistency between top-level and nested payloads
   - app certificate chain validation against a pinned trust store
   - Intel PCK certificate chain validation against a pinned trust store
   - Intel quote signature validation against the embedded attestation key
   - QE report signature validation against the Intel PCK leaf certificate
   - QE report-data binding between the attestation key and QE auth data
   - report-data binding between signing address and nonce
   - TDX measurement checks (`MRTD`, `RTMR0-3`, `MRCONFIGID`)
   - event log consistency checks against the `info` / `tcb_info` block
   - key-provider metadata consistency checks
   - NVIDIA certificate-chain validation against a pinned trust store
   - NVIDIA raw-evidence parsing, signature verification, nonce binding, FWID binding, and architecture binding
   - advisory inspection of embedded Venice or NRAS provenance already present in the raw report
7. `buildVerificationSummary(...)` classifies the result:
   - `Verified`: all blocking local checks passed and the app independently completed all supported cryptographic verification
   - `Partially verified`: all blocking local checks passed, but the raw report did not contain enough supported evidence to complete every independent verification path
   - `Verification failed`: one or more blocking local checks failed
8. React components render:
   - a verdict summary card
   - a decoded metadata panel
   - a checklist of individual checks including source, domain, and severity

## Current Scope and Limits

This repository now performs a materially stronger local verification pass than the original implementation, but it still does **not** ship every artifact needed for a repo-local end-to-end `Verified` golden Venice fixture.

The main remaining limits are:

- there is not yet a committed Venice report fixture that reaches `Verified` fully from a single repo-local raw report
- Intel's published QVL `AttestationApp/sampleData/tdx` fixture set contains a QE identity whose signed `mrsigner` does not match the accompanying `quote.dat`, so it is useful as a regression sample but not as a full-positive golden
- separate Venice response-signature metadata is still out of scope for this verifier

That means a positive result in this app should currently be read as:

- blocking local bindings, schema checks, and supported certificate/signature checks passed, and
- unsupported evidence paths remained partial instead of being silently treated as verified

It should be read as proof only for the evidence paths the app independently re-derived from the supplied raw report bytes.

## Repo Layout

```text
public/                 Static Venice assets
src/app.tsx             Main application shell
src/components/         UI panels for input, verdicts, metadata, and checks
src/lib/normalize.ts    Async parse + verify entrypoint and verdict builder
src/lib/verifier.ts     Local certificate, quote, and consistency checks
src/lib/schema.ts       Typed zod schemas and normalization helpers
src/lib/certificates.ts X.509 chain validation helpers
tests/                  Parser, verdict, and UI regression tests
```

## Run It Locally

### Prerequisites

- Node.js
- npm

### Install

```bash
npm install
```

### Start the dev server

```bash
npm run dev
```

Vite will print a local URL, usually `http://localhost:5173`.

### Run the test suite

```bash
npm test
```

Notes:

- The test suite is repo-local and does not depend on a machine-specific report path.
- Current tests cover schema failures, verdict construction, unsupported quote versions, explicit verify UI flow, raw-report-only verification behavior, and NVIDIA raw-evidence verification.
- The remaining fixture gap is a single repo-local Venice report that reaches `Verified` end-to-end.

### Build for production

```bash
npm run build
```

### Preview the production build

```bash
npm run preview
```

## Using the App

1. Start the dev server.
2. Open the local Vite URL in your browser.
3. Paste a Venice attestation report into the textarea, or upload a JSON file.
4. Click `Verify report`.
5. Review the verdict card, decoded metadata, and per-check diagnostics.

No backend or environment-variable setup is required for the current app.

## Deployment Notes

- The app is still a static frontend with no backend verifier.
- The production build code-splits the heavy verifier path so the landing bundle stays smaller and the crypto/X.509 stack loads on demand.
- Static hosts should set a CSP and other security headers at the edge. This repo does not yet ship host-specific config for Vercel, Netlify, or Cloudflare Pages.

## Audit Prompt for an Agentic Coding Tool

Use the prompt below as-is if you want another coding agent to audit this repository.

```text
Audit this repository as a security- and correctness-focused code review.

Repository context:
- This is a frontend-only Venice attestation verifier built with Vite, React, and TypeScript.
- The main logic lives in src/lib/normalize.ts and src/lib/verifier.ts.
- The app parses pasted/uploaded JSON attestation reports, normalizes them, runs deterministic local checks, and renders a verdict in the browser.
- Current implementation performs local schema, binding, certificate, Intel quote-cryptography, and NVIDIA raw-evidence checks from the raw report alone. Review whether any result can still overclaim authority and whether the remaining fixture gaps could hide end-to-end regressions.

Your objectives:
- Find bugs, security risks, misleading verification behavior, and incorrect assumptions.
- Prioritize findings that could cause a false positive verification result, a missed invalid report, or a misleading security claim.
- Review parsing, normalization, hex/address handling, quote decoding offsets, event-log comparisons, embedded server_verification trust assumptions, and verdict construction.
- Check whether malformed or adversarial JSON inputs can produce incorrect passes, silent skips, confusing partial-verification states, or unsafe rendering behavior.
- Check whether tests are missing for important negative cases and edge cases.
- Call out places where the code still treats unsupported evidence paths as partial rather than fully verified.

Expected output format:
1. Findings first, ordered by severity.
2. For each finding, include file path, line number, risk, and a concrete explanation.
3. Then list open questions or assumptions.
4. Then give a short summary of overall verification confidence and the biggest missing tests.

Important review lens:
- Treat this like attestation/security code, not a generic frontend app.
- Be skeptical of anything that could let a crafted report appear "Verified" or "Partially verified" when it should not.
- Distinguish clearly between deterministic local consistency checks and true cryptographic verification.
```

## Development Notes

- The app is intentionally frontend only.
- The verification engine is implemented with plain TypeScript functions, which makes it straightforward to test independently of the React UI.
- `viem` is used for Ethereum-style hex/address utilities and hashing needed for signing-address derivation.
- `@peculiar/x509` is used for local certificate parsing, chain building, and CRL parsing.
- The UI is a thin layer over the parser/verifier pipeline, so most correctness work should focus on `src/lib`.
