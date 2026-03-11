# Venice Attestation Verifier

`Venice Attestation Verifier` is a frontend-only app for inspecting a Venice attestation report in the browser and turning it into a concrete verification verdict.

You can paste raw JSON or upload a report file, and the app will:

- parse and normalize the report
- surface structural problems early
- run deterministic local consistency checks
- show a verdict of `Verified`, `Partially verified`, or `Verification failed`

## Purpose

This repo exists to make Venice attestation reports easier to inspect without sending the report to a backend service. The current implementation is focused on browser-side validation of report structure and internal bindings rather than full end-to-end cryptographic attestation verification.

Today, the app is best understood as a transparent verifier UI plus a deterministic local checking engine.

## How It Works

The app is a Vite + React + TypeScript single-page application.

### Runtime flow

1. The user pastes JSON into the textarea or uploads a file.
2. `src/app.tsx` passes the raw input to `parseReportSource(...)` in `src/lib/normalize.ts`.
3. The parser:
   - validates that the input is JSON
   - checks that the top level is an object
   - checks for required top-level fields
   - normalizes `nvidia_payload` when it arrives as a JSON string
   - records basic shape checks for `event_log` and `info`
4. The normalized report is passed to `verifyNormalizedReport(...)` in `src/lib/verifier.ts`.
5. The verifier runs deterministic local checks, including:
   - signing public key -> Ethereum address derivation
   - equality checks across duplicated signing key fields
   - nonce consistency between top-level and nested payloads
   - Intel TDX quote decoding
   - report-data binding between signing address and nonce
   - TDX measurement checks (`MRTD`, `RTMR0-3`, `MRCONFIGID`)
   - event log consistency checks against the `info` / `tcb_info` block
   - key-provider metadata consistency checks
   - inspection of embedded `server_verification` claims when present
6. `buildVerificationSummary(...)` classifies the result:
   - `Verified`: supported local checks passed and embedded TDX/NVIDIA verification claims passed
   - `Partially verified`: local checks passed, but embedded cryptographic verification claims were missing or incomplete
   - `Verification failed`: one or more supported checks failed
7. React components render:
   - a verdict summary card
   - a decoded metadata panel
   - a checklist of individual checks and their JSON paths

## Current Scope and Limits

This repository does **not** yet perform the full cryptographic evidence verification implied by production attestation systems.

According to `IMPLEMENTATION_PLAN.md`, these areas are still pending:

- certificate validation against pinned trust anchors
- full NVIDIA evidence verification
- full Intel TDX quote verification

That means a positive result in this app should currently be read as:

- local bindings and consistency checks passed, and
- the report may include embedded claims saying server-side verification succeeded

It should not be read as proof that this repo independently re-derived every cryptographic guarantee from raw evidence.

## Repo Layout

```text
public/                 Static Venice assets
src/app.tsx             Main application shell
src/components/         UI panels for input, verdicts, metadata, and checks
src/lib/normalize.ts    Parsing, normalization, summary building, verdict logic
src/lib/verifier.ts     Deterministic verification checks and TDX decoding
src/lib/schema.ts       Required-field and record helpers
tests/normalize.test.ts Parser and verification regression tests
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

- The test suite includes basic parser tests that run everywhere.
- Two tests use a hard-coded sample report path in `tests/normalize.test.ts`.
- If that sample file is not present on your machine, those sample-based tests exit early instead of failing.

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
4. Review the verdict card, decoded metadata, and per-check diagnostics.

No backend or environment-variable setup is required for the current app.

## Audit Prompt for an Agentic Coding Tool

Use the prompt below as-is if you want another coding agent to audit this repository.

```text
Audit this repository as a security- and correctness-focused code review.

Repository context:
- This is a frontend-only Venice attestation verifier built with Vite, React, and TypeScript.
- The main logic lives in src/lib/normalize.ts and src/lib/verifier.ts.
- The app parses pasted/uploaded JSON attestation reports, normalizes them, runs deterministic local checks, and renders a verdict in the browser.
- Current implementation intentionally does not yet do full certificate-chain validation or full raw-evidence cryptographic verification; review whether the UI and code make that scope clear enough and whether any checks overclaim what they prove.

Your objectives:
- Find bugs, security risks, misleading verification behavior, and incorrect assumptions.
- Prioritize findings that could cause a false positive verification result, a missed invalid report, or a misleading security claim.
- Review parsing, normalization, hex/address handling, quote decoding offsets, event-log comparisons, embedded server_verification trust assumptions, and verdict construction.
- Check whether malformed or adversarial JSON inputs can produce incorrect passes, silent skips, confusing partial-verification states, or unsafe rendering behavior.
- Check whether tests are missing for important negative cases and edge cases.
- Call out places where the code relies on embedded verification claims instead of independently verifying evidence.

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
- The UI is a thin layer over the parser/verifier pipeline, so most correctness work should focus on `src/lib`.
