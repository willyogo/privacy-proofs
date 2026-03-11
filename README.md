# Venice Attestation Verifier

`Venice Attestation Verifier` is a frontend-only app for inspecting a Venice attestation report in the browser and turning it into a concrete verification verdict.

You can paste raw JSON or upload a report file, and the app will:

- parse and normalize the report with explicit schemas
- validate local bindings, certificate chains, and Intel TDX quote signatures in the browser
- optionally accept a collateral bundle for follow-on validation inputs
- show a verdict of `Verified`, `Partially verified`, or `Verification failed`

## Purpose

This repo exists to make Venice attestation reports easier to inspect without sending the report to a backend service. The current build performs real local validation for report structure, internal bindings, certificate chains, and the Intel TDX quote signature path.

Today, the app is best understood as a transparent verifier UI with an independent local verification engine that still keeps unsupported evidence paths in a partial state instead of over-claiming verification.

## How It Works

The app is a Vite + React + TypeScript single-page application.

### Runtime flow

1. The user pastes JSON into the textarea or uploads a report file.
2. The user can optionally paste or upload a collateral bundle JSON file.
3. The user clicks `Verify report`.
4. `src/app.tsx` passes the raw inputs to `parseReportSource(...)` in `src/lib/normalize.ts`.
5. The parser:
   - validates that the report and optional collateral bundle are JSON
   - validates the report against explicit `zod` schemas
   - normalizes `nvidia_payload` when it arrives as a JSON string
   - records precise schema-path failures when parsing fails
6. `parseReportSource(...)` lazy-loads `verifyNormalizedReport(...)` from `src/lib/verifier.ts`.
7. The verifier runs local checks, including:
   - signing public key -> Ethereum address derivation
   - equality checks across duplicated signing key fields
   - nonce consistency between top-level and nested payloads
   - app certificate chain validation against a pinned root fingerprint
   - Intel PCK certificate chain validation against a pinned root fingerprint
   - Intel quote signature validation against the embedded attestation key
   - QE report signature validation against the Intel PCK leaf certificate
   - QE report-data binding between the attestation key and QE auth data
   - report-data binding between signing address and nonce
   - TDX measurement checks (`MRTD`, `RTMR0-3`, `MRCONFIGID`)
   - event log consistency checks against the `info` / `tcb_info` block
   - key-provider metadata consistency checks
   - NVIDIA certificate-chain validation against a pinned root fingerprint
   - advisory inspection of embedded `server_verification` claims
   - advisory tracking of fetched revocation collateral when available
8. `buildVerificationSummary(...)` classifies the result:
   - `Verified`: all blocking local checks passed and the app independently completed all supported cryptographic verification
   - `Partially verified`: all blocking local checks passed, but unsupported or missing evidence/collateral still prevents a full proof
   - `Verification failed`: one or more blocking local checks failed
9. React components render:
   - a verdict summary card
   - a decoded metadata panel
   - a checklist of individual checks including source, domain, and severity

## Current Scope and Limits

This repository now performs a materially stronger local verification pass than the original implementation, but it still does **not** complete every evidence path required for unconditional production-grade attestation proof.

According to `IMPLEMENTATION_PLAN.md`, these areas are still pending:

- full NVIDIA raw-evidence signature verification
- full Intel QE identity / TCB collateral validation
- a repo-local golden attestation fixture that exercises the full real-world quote path end-to-end

That means a positive result in this app should currently be read as:

- blocking local bindings, schema checks, and supported certificate/signature checks passed, and
- unsupported evidence paths remained partial instead of being silently treated as verified

It should not be read as proof that this repo independently re-derived every cryptographic guarantee from raw Intel and NVIDIA evidence yet.

## Repo Layout

```text
public/                 Static Venice assets
src/app.tsx             Main application shell
src/components/         UI panels for input, verdicts, metadata, and checks
src/lib/normalize.ts    Async parse + verify entrypoint and verdict builder
src/lib/verifier.ts     Local certificate, quote, and consistency checks
src/lib/schema.ts       Typed zod schemas and normalization helpers
src/lib/certificates.ts X.509 chain and revocation helpers
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
- Current tests focus on schema failures, verdict construction, unsupported quote versions, and the explicit verify UI flow.
- A committed golden fixture for the full real-world attestation path is still pending.

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
4. Optionally paste or upload a collateral bundle JSON file.
5. Click `Verify report`.
6. Review the verdict card, decoded metadata, and per-check diagnostics.

No backend or environment-variable setup is required for the current app.

## Collateral Bundle Shape

The optional collateral bundle currently accepts a JSON object with these top-level keys:

```json
{
  "intel": {
    "pckCrl": "-----BEGIN X509 CRL-----...",
    "qeIdentity": {},
    "tcbInfo": {}
  },
  "nvidia": {
    "crls": ["-----BEGIN X509 CRL-----..."],
    "certBundle": "-----BEGIN CERTIFICATE-----..."
  }
}
```

Only `intel.pckCrl` and `nvidia.crls` are actively consumed by the current build. Other fields are accepted so the interface is stable as the remaining collateral validation work lands.

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
- Current implementation performs local schema, binding, certificate, and Intel quote signature checks, but it still does not complete full NVIDIA raw-evidence verification or full Intel collateral validation; review whether the UI and code make that scope clear enough and whether any checks overclaim what they prove.

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
