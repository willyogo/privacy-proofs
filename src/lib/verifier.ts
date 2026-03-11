import { bytesToHex, getAddress, hexToBytes, keccak256 } from "viem";
import type { CheckResult } from "./check-result";
import { isRecord } from "./schema";
import type { RawAttestationReport } from "./types";

type VerificationAnalysis = {
  checks: CheckResult[];
  derivedSigningAddress?: string;
  embeddedClaimsAvailable: boolean;
  embeddedClaimsPassed: boolean;
  quoteReportData?: string;
  verifiedAt?: string;
};

const TDX_BODY_OFFSET = 48;
const TDX_FIELD_LAYOUT = {
  mrOwner: { offset: 64, length: 48 },
  mrOwnerConfig: { offset: 112, length: 48 },
  tdAttributes: { offset: 120, length: 8 },
  xfam: { offset: 128, length: 8 },
  mrtd: { offset: 136, length: 48 },
  mrConfigId: { offset: 184, length: 48 },
  rtmr0: { offset: 328, length: 48 },
  rtmr1: { offset: 376, length: 48 },
  rtmr2: { offset: 424, length: 48 },
  rtmr3: { offset: 472, length: 48 },
  reportData: { offset: 520, length: 64 },
} as const;

type DecodedQuote = {
  mrConfigId: string;
  mrOwner: string;
  mrOwnerConfig: string;
  mrtd: string;
  reportData: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  tdAttributes: string;
  version: number;
  xfam: string;
};

export function verifyNormalizedReport(
  report: RawAttestationReport,
): VerificationAnalysis {
  const checks: CheckResult[] = [];
  let derivedSigningAddress: string | undefined;
  let quoteReportData: string | undefined;
  let embeddedClaimsAvailable = false;
  let embeddedClaimsPassed = false;
  let verifiedAt: string | undefined;

  const publicKey = normalizeHex(report.signing_public_key);
  const signingKey = normalizeHex(report.signing_key);
  const reportedAddress = normalizeAddress(report.signing_address);
  const nonce = normalizeHex(report.nonce);
  const requestNonce = normalizeHex(report.request_nonce);

  if (publicKey && publicKey.length === 130 && publicKey.startsWith("04")) {
    derivedSigningAddress = deriveEthereumAddress(publicKey);

    checks.push({
      id: "signing-address-binding",
      label: "Verify signing public key binding",
      status:
        reportedAddress && derivedSigningAddress === reportedAddress
          ? "pass"
          : "fail",
      description:
        reportedAddress && derivedSigningAddress === reportedAddress
          ? "The signing public key derives to the reported Ethereum address."
          : "The signing public key does not derive to the reported signing address.",
      jsonPath: "$.signing_public_key",
    });
  } else {
    checks.push({
      id: "signing-address-binding",
      label: "Verify signing public key binding",
      status: "fail",
      description:
        "The signing public key is missing or not a 65-byte uncompressed secp256k1 public key.",
      jsonPath: "$.signing_public_key",
    });
  }

  checks.push({
    id: "signing-key-consistency",
    label: "Check signing key consistency",
    status:
      publicKey && signingKey && publicKey.toLowerCase() === signingKey.toLowerCase()
        ? "pass"
        : "fail",
    description:
      publicKey && signingKey && publicKey.toLowerCase() === signingKey.toLowerCase()
        ? "The duplicated signing key fields agree."
        : "The signing key fields disagree or one is missing.",
    jsonPath: "$.signing_key",
  });

  checks.push({
    id: "request-nonce-consistency",
    label: "Check top-level nonce binding",
    status: nonce && requestNonce && nonce === requestNonce ? "pass" : "fail",
    description:
      nonce && requestNonce && nonce === requestNonce
        ? "The top-level nonce matches the request nonce."
        : "The top-level nonce does not match the request nonce.",
    jsonPath: "$.nonce",
  });

  const nvidiaPayload = isRecord(report.nvidia_payload)
    ? report.nvidia_payload
    : undefined;
  const nvidiaNonce = normalizeHex(nvidiaPayload?.nonce);

  checks.push({
    id: "nvidia-nonce-binding",
    label: "Check NVIDIA nonce binding",
    status: nonce && nvidiaNonce && nonce === nvidiaNonce ? "pass" : "fail",
    description:
      nonce && nvidiaNonce && nonce === nvidiaNonce
        ? "The NVIDIA payload nonce matches the attestation nonce."
        : "The NVIDIA payload nonce does not match the attestation nonce.",
    jsonPath: "$.nvidia_payload.nonce",
  });

  const evidenceList = Array.isArray(nvidiaPayload?.evidence_list)
    ? nvidiaPayload.evidence_list
    : [];

  checks.push({
    id: "nvidia-evidence-shape",
    label: "Inspect NVIDIA evidence bundle",
    status:
      evidenceList.length > 0 &&
      evidenceList.every(
        (entry) =>
          isRecord(entry) &&
          typeof entry.certificate === "string" &&
          typeof entry.evidence === "string",
      )
        ? "pass"
        : "fail",
    description:
      evidenceList.length > 0
        ? `The NVIDIA payload includes ${evidenceList.length} evidence entries with certificate and evidence blobs.`
        : "The NVIDIA payload is missing its evidence list.",
    jsonPath: "$.nvidia_payload.evidence_list",
  });

  const quote = decodeTdxQuote(report.intel_quote);

  if (quote) {
    quoteReportData = quote.reportData;

    checks.push({
      id: "tdx-quote-shape",
      label: "Decode Intel TDX quote",
      status: quote.version === 4 ? "pass" : "info",
      description:
        quote.version === 4
          ? "The Intel quote decoded successfully as a TDX v4 quote."
          : `The Intel quote decoded successfully with version ${quote.version}.`,
      jsonPath: "$.intel_quote",
    });

    const expectedReportData =
      reportedAddress && nonce
        ? `${reportedAddress.slice(2).toLowerCase()}${"0".repeat(24)}${nonce}`
        : undefined;

    checks.push({
      id: "tdx-report-data-binding",
      label: "Check TDX quote report data",
      status:
        expectedReportData && quote.reportData === expectedReportData
          ? "pass"
          : "fail",
      description:
        expectedReportData && quote.reportData === expectedReportData
          ? "The quote report data binds the signing address and nonce exactly as expected."
          : "The quote report data does not match the expected address-plus-nonce binding.",
      jsonPath: "$.intel_quote",
    });

    checks.push(
      ...buildMeasurementChecks({
        quote,
        report,
      }),
    );
  } else {
    checks.push({
      id: "tdx-quote-shape",
      label: "Decode Intel TDX quote",
      status: "fail",
      description:
        "The Intel quote is missing, malformed, or too short to decode its measurements and report data.",
      jsonPath: "$.intel_quote",
    });
  }

  checks.push(...buildEventLogChecks(report));
  checks.push(...buildKeyProviderChecks(report));

  const serverClaims = evaluateEmbeddedClaims(report, derivedSigningAddress);
  checks.push(...serverClaims.checks);
  embeddedClaimsAvailable = serverClaims.available;
  embeddedClaimsPassed = serverClaims.passed;
  verifiedAt = serverClaims.verifiedAt;

  return {
    checks,
    derivedSigningAddress,
    embeddedClaimsAvailable,
    embeddedClaimsPassed,
    quoteReportData,
    verifiedAt,
  };
}

function buildMeasurementChecks({
  quote,
  report,
}: {
  quote: DecodedQuote;
  report: RawAttestationReport;
}): CheckResult[] {
  const checks: CheckResult[] = [];
  const info = isRecord(report.info) ? report.info : undefined;
  const tcbInfo = isRecord(info?.tcb_info) ? info.tcb_info : undefined;
  const composeHash = normalizeHex(info?.compose_hash);

  checks.push({
    id: "tdx-mrtd",
    label: "Check TDX measurement: MR TD",
    status:
      normalizeHex(tcbInfo?.mrtd) && quote.mrtd === normalizeHex(tcbInfo?.mrtd)
        ? "pass"
        : "fail",
    description:
      normalizeHex(tcbInfo?.mrtd) && quote.mrtd === normalizeHex(tcbInfo?.mrtd)
        ? "The quote MR TD matches the reported TCB info."
        : "The quote MR TD does not match the reported TCB info.",
    jsonPath: "$.info.tcb_info.mrtd",
  });

  for (const rtmr of ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] as const) {
    const expected = normalizeHex(tcbInfo?.[rtmr]);
    const actual = quote[rtmr];

    checks.push({
      id: `tdx-${rtmr}`,
      label: `Check TDX measurement: ${rtmr.toUpperCase()}`,
      status: expected && actual === expected ? "pass" : "fail",
      description:
        expected && actual === expected
          ? `${rtmr.toUpperCase()} matches the reported TCB info.`
          : `${rtmr.toUpperCase()} does not match the reported TCB info.`,
      jsonPath: `$.info.tcb_info.${rtmr}`,
    });
  }

  checks.push({
    id: "tdx-compose-hash",
    label: "Check quote MRCONFIGID against compose hash",
    status:
      composeHash &&
      quote.mrConfigId.length >= 66 &&
      quote.mrConfigId.slice(2, 66) === composeHash
        ? "pass"
        : "fail",
    description:
      composeHash &&
      quote.mrConfigId.length >= 66 &&
      quote.mrConfigId.slice(2, 66) === composeHash
        ? "The quote MRCONFIGID embeds the reported compose hash."
        : "The quote MRCONFIGID does not embed the reported compose hash.",
    jsonPath: "$.info.compose_hash",
  });

  return checks;
}

function buildEventLogChecks(report: RawAttestationReport): CheckResult[] {
  const eventMap = collectNamedEventPayloads(report.event_log);
  const info = isRecord(report.info) ? report.info : undefined;
  const tcbInfo = isRecord(info?.tcb_info) ? info.tcb_info : undefined;
  const checks: CheckResult[] = [];

  checks.push({
    id: "event-log-app-id",
    label: "Check event log app ID binding",
    status:
      normalizeHex(eventMap["app-id"]) &&
      normalizeHex(info?.app_id) &&
      normalizeHex(eventMap["app-id"]) === normalizeHex(info?.app_id)
        ? "pass"
        : "fail",
    description:
      normalizeHex(eventMap["app-id"]) &&
      normalizeHex(info?.app_id) &&
      normalizeHex(eventMap["app-id"]) === normalizeHex(info?.app_id)
        ? "The event log app-id matches the info block."
        : "The event log app-id does not match the info block.",
    jsonPath: "$.event_log",
  });

  checks.push({
    id: "event-log-compose-hash",
    label: "Check event log compose hash binding",
    status:
      normalizeHex(eventMap["compose-hash"]) &&
      normalizeHex(info?.compose_hash) &&
      normalizeHex(eventMap["compose-hash"]) === normalizeHex(info?.compose_hash)
        ? "pass"
        : "fail",
    description:
      normalizeHex(eventMap["compose-hash"]) &&
      normalizeHex(info?.compose_hash) &&
      normalizeHex(eventMap["compose-hash"]) === normalizeHex(info?.compose_hash)
        ? "The event log compose hash matches the info block."
        : "The event log compose hash does not match the info block.",
    jsonPath: "$.event_log",
  });

  checks.push({
    id: "event-log-instance-id",
    label: "Check event log instance ID binding",
    status:
      normalizeHex(eventMap["instance-id"]) &&
      normalizeHex(info?.instance_id) &&
      normalizeHex(eventMap["instance-id"]) === normalizeHex(info?.instance_id)
        ? "pass"
        : "fail",
    description:
      normalizeHex(eventMap["instance-id"]) &&
      normalizeHex(info?.instance_id) &&
      normalizeHex(eventMap["instance-id"]) === normalizeHex(info?.instance_id)
        ? "The event log instance-id matches the info block."
        : "The event log instance-id does not match the info block.",
    jsonPath: "$.event_log",
  });

  checks.push({
    id: "event-log-os-image-hash",
    label: "Check event log OS image hash binding",
    status:
      normalizeHex(eventMap["os-image-hash"]) &&
      normalizeHex(tcbInfo?.os_image_hash) &&
      normalizeHex(eventMap["os-image-hash"]) ===
        normalizeHex(tcbInfo?.os_image_hash)
        ? "pass"
        : "fail",
    description:
      normalizeHex(eventMap["os-image-hash"]) &&
      normalizeHex(tcbInfo?.os_image_hash) &&
      normalizeHex(eventMap["os-image-hash"]) ===
        normalizeHex(tcbInfo?.os_image_hash)
        ? "The event log OS image hash matches the TCB info."
        : "The event log OS image hash does not match the TCB info.",
    jsonPath: "$.event_log",
  });

  if (Array.isArray(report.event_log) && Array.isArray(tcbInfo?.event_log)) {
    checks.push({
      id: "event-log-duplication",
      label: "Check duplicated event log consistency",
      status:
        JSON.stringify(report.event_log) === JSON.stringify(tcbInfo.event_log)
          ? "pass"
          : "fail",
      description:
        JSON.stringify(report.event_log) === JSON.stringify(tcbInfo.event_log)
          ? "The top-level event log matches the copy embedded in the TCB info."
          : "The top-level event log differs from the copy embedded in the TCB info.",
      jsonPath: "$.info.tcb_info.event_log",
    });
  }

  return checks;
}

function buildKeyProviderChecks(report: RawAttestationReport): CheckResult[] {
  const info = isRecord(report.info) ? report.info : undefined;
  const eventMap = collectNamedEventPayloads(report.event_log);
  const encodedKeyProviderPayload = normalizeHex(eventMap["key-provider"]);
  const checks: CheckResult[] = [];

  const infoKeyProvider = parseJsonObject(info?.key_provider_info);
  const eventKeyProvider =
    encodedKeyProviderPayload !== undefined
      ? parseJsonObject(hexToUtf8(encodedKeyProviderPayload))
      : undefined;

  checks.push({
    id: "key-provider-binding",
    label: "Check key provider metadata binding",
    status:
      infoKeyProvider &&
      eventKeyProvider &&
      JSON.stringify(infoKeyProvider) === JSON.stringify(eventKeyProvider)
        ? "pass"
        : "fail",
    description:
      infoKeyProvider &&
      eventKeyProvider &&
      JSON.stringify(infoKeyProvider) === JSON.stringify(eventKeyProvider)
        ? "The key provider metadata matches between the info block and event log."
        : "The key provider metadata does not match between the info block and event log.",
    jsonPath: "$.info.key_provider_info",
  });

  return checks;
}

function evaluateEmbeddedClaims(
  report: RawAttestationReport,
  derivedSigningAddress?: string,
): {
  available: boolean;
  checks: CheckResult[];
  passed: boolean;
  verifiedAt?: string;
} {
  const checks: CheckResult[] = [];
  const serverVerification = isRecord(report.server_verification)
    ? report.server_verification
    : undefined;

  if (!serverVerification) {
    checks.push({
      id: "embedded-verification-claims",
      label: "Inspect embedded verification claims",
      status: "info",
      description:
        "No embedded server verification block was present, so the report can only be partially verified locally.",
      jsonPath: "$.server_verification",
    });

    return {
      available: false,
      checks,
      passed: false,
    };
  }

  const tdx = isRecord(serverVerification.tdx) ? serverVerification.tdx : undefined;
  const nvidia = isRecord(serverVerification.nvidia)
    ? serverVerification.nvidia
    : undefined;
  const tdxMeasurements = isRecord(tdx?.measurements) ? tdx.measurements : undefined;
  const nvidiaCertStatus = isRecord(nvidia?.certificateChainStatus)
    ? nvidia.certificateChainStatus
    : undefined;
  const verifiedAt =
    typeof serverVerification.verifiedAt === "string"
      ? serverVerification.verifiedAt
      : undefined;

  checks.push({
    id: "embedded-report-verified-flag",
    label: "Inspect embedded verified flag",
    status: report.verified === true ? "pass" : "fail",
    description:
      report.verified === true
        ? "The report's embedded verified flag is set."
        : "The report's embedded verified flag is not set.",
    jsonPath: "$.verified",
  });

  checks.push({
    id: "embedded-tdx-claims",
    label: "Inspect embedded TDX verification claims",
    status:
      tdx?.valid === true &&
      tdx.signatureValid === true &&
      tdx.certificateChainValid === true &&
      tdx.rootCaPinned === true &&
      tdx.attestationKeyMatch === true &&
      (!isRecord(tdx.crlCheck) || tdx.crlCheck.revoked === false)
        ? "pass"
        : "fail",
    description:
      tdx?.valid === true &&
      tdx.signatureValid === true &&
      tdx.certificateChainValid === true &&
      tdx.rootCaPinned === true &&
      tdx.attestationKeyMatch === true &&
      (!isRecord(tdx.crlCheck) || tdx.crlCheck.revoked === false)
        ? "The embedded verifier reports a valid TDX quote, certificate chain, and non-revoked attestation path."
        : "The embedded TDX verification claims are missing or indicate a failure.",
    jsonPath: "$.server_verification.tdx",
  });

  checks.push({
    id: "embedded-nvidia-claims",
    label: "Inspect embedded NVIDIA verification claims",
    status:
      nvidia?.valid === true &&
      nvidia.signatureVerified === true &&
      nvidiaCertStatus?.valid === true &&
      nvidiaCertStatus?.intermediatePinned === true
        ? "pass"
        : "fail",
    description:
      nvidia?.valid === true &&
      nvidia.signatureVerified === true &&
      nvidiaCertStatus?.valid === true &&
      nvidiaCertStatus?.intermediatePinned === true
        ? "The embedded verifier reports a valid NVIDIA evidence chain and signature."
        : "The embedded NVIDIA verification claims are missing or indicate a failure.",
    jsonPath: "$.server_verification.nvidia",
  });

  const embeddedAddress = normalizeAddress(
    isRecord(serverVerification.signingAddressBinding)
      ? serverVerification.signingAddressBinding.reportDataAddress
      : undefined,
  );

  checks.push({
    id: "embedded-binding-claims",
    label: "Inspect embedded nonce and address binding claims",
    status:
      isRecord(serverVerification.signingAddressBinding) &&
      serverVerification.signingAddressBinding.bound === true &&
      embeddedAddress !== undefined &&
      embeddedAddress === derivedSigningAddress &&
      isRecord(serverVerification.nonceBinding) &&
      serverVerification.nonceBinding.bound === true &&
      isRecord(serverVerification.nvidiaNonceBinding) &&
      serverVerification.nvidiaNonceBinding.bound === true
        ? "pass"
        : "fail",
    description:
      isRecord(serverVerification.signingAddressBinding) &&
      serverVerification.signingAddressBinding.bound === true &&
      embeddedAddress !== undefined &&
      embeddedAddress === derivedSigningAddress &&
      isRecord(serverVerification.nonceBinding) &&
      serverVerification.nonceBinding.bound === true &&
      isRecord(serverVerification.nvidiaNonceBinding) &&
      serverVerification.nvidiaNonceBinding.bound === true
        ? "The embedded verifier reports successful address, nonce, and NVIDIA nonce bindings."
        : "The embedded binding claims are missing or inconsistent with the locally derived address.",
    jsonPath: "$.server_verification",
  });

  if (tdxMeasurements) {
    checks.push({
      id: "embedded-tdx-measurements",
      label: "Inspect embedded TDX measurement claims",
      status:
        typeof tdxMeasurements.mrtd === "string" &&
        typeof tdxMeasurements.mrconfigid === "string" &&
        typeof tdxMeasurements.rtmr0 === "string" &&
        typeof tdxMeasurements.rtmr1 === "string" &&
        typeof tdxMeasurements.rtmr2 === "string" &&
        typeof tdxMeasurements.rtmr3 === "string"
          ? "pass"
          : "fail",
      description:
        typeof tdxMeasurements.mrtd === "string" &&
        typeof tdxMeasurements.mrconfigid === "string" &&
        typeof tdxMeasurements.rtmr0 === "string" &&
        typeof tdxMeasurements.rtmr1 === "string" &&
        typeof tdxMeasurements.rtmr2 === "string" &&
        typeof tdxMeasurements.rtmr3 === "string"
          ? "The embedded verifier provided the decoded TDX measurement set."
          : "The embedded TDX measurement claims are incomplete.",
      jsonPath: "$.server_verification.tdx.measurements",
    });
  }

  const passed = checks.every((check) => check.status !== "fail");

  return {
    available: true,
    checks,
    passed,
    verifiedAt,
  };
}

function decodeTdxQuote(value: unknown): DecodedQuote | undefined {
  const quoteHex = normalizeHex(value);
  if (!quoteHex) {
    return undefined;
  }

  try {
    const bytes = hexToBytes(`0x${quoteHex}`);
    if (bytes.length < TDX_BODY_OFFSET + TDX_FIELD_LAYOUT.reportData.offset + 64) {
      return undefined;
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    return {
      version: view.getUint16(0, true),
      mrOwner: extractQuoteField(bytes, TDX_FIELD_LAYOUT.mrOwner.offset, 48),
      mrOwnerConfig: extractQuoteField(
        bytes,
        TDX_FIELD_LAYOUT.mrOwnerConfig.offset,
        48,
      ),
      tdAttributes: extractQuoteField(
        bytes,
        TDX_FIELD_LAYOUT.tdAttributes.offset,
        8,
      ),
      xfam: extractQuoteField(bytes, TDX_FIELD_LAYOUT.xfam.offset, 8),
      mrtd: extractQuoteField(bytes, TDX_FIELD_LAYOUT.mrtd.offset, 48),
      mrConfigId: extractQuoteField(bytes, TDX_FIELD_LAYOUT.mrConfigId.offset, 48),
      rtmr0: extractQuoteField(bytes, TDX_FIELD_LAYOUT.rtmr0.offset, 48),
      rtmr1: extractQuoteField(bytes, TDX_FIELD_LAYOUT.rtmr1.offset, 48),
      rtmr2: extractQuoteField(bytes, TDX_FIELD_LAYOUT.rtmr2.offset, 48),
      rtmr3: extractQuoteField(bytes, TDX_FIELD_LAYOUT.rtmr3.offset, 48),
      reportData: extractQuoteField(bytes, TDX_FIELD_LAYOUT.reportData.offset, 64),
    };
  } catch {
    return undefined;
  }
}

function extractQuoteField(
  bytes: Uint8Array,
  offset: number,
  length: number,
): string {
  return bytesToHex(
    bytes.slice(TDX_BODY_OFFSET + offset, TDX_BODY_OFFSET + offset + length),
  ).slice(2);
}

function collectNamedEventPayloads(value: unknown): Record<string, string> {
  if (!Array.isArray(value)) {
    return {};
  }

  const namedPayloads: Record<string, string> = {};

  for (const entry of value) {
    if (!isRecord(entry)) {
      continue;
    }

    if (typeof entry.event !== "string" || entry.event.trim().length === 0) {
      continue;
    }

    if (typeof entry.event_payload !== "string") {
      continue;
    }

    namedPayloads[entry.event.trim()] = entry.event_payload;
  }

  return namedPayloads;
}

function deriveEthereumAddress(publicKeyHex: string): string {
  const hash = keccak256(`0x${publicKeyHex.slice(2)}`);
  return getAddress(`0x${hash.slice(-40)}`);
}

function normalizeHex(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim().replace(/^0x/i, "");
  if (trimmed.length === 0 || trimmed.length % 2 !== 0) {
    return undefined;
  }

  return /^[0-9a-fA-F]+$/.test(trimmed) ? trimmed.toLowerCase() : undefined;
}

function normalizeAddress(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  try {
    return getAddress(value);
  } catch {
    return undefined;
  }
}

function hexToUtf8(value: string): string {
  return new TextDecoder().decode(hexToBytes(`0x${value}`));
}

function parseJsonObject(value: unknown): Record<string, unknown> | undefined {
  if (isRecord(value)) {
    return value;
  }

  if (typeof value !== "string") {
    return undefined;
  }

  try {
    const parsed = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}
