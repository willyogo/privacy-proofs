import { bytesToHex, getAddress, hexToBytes, keccak256 } from "viem";
import type { CheckResult, EvidenceDomain } from "./check-result";
import { validateCertificateChain } from "./certificates";
import { concatBytes, sha256Hex } from "./crypto";
import {
  asInfoBlock,
  asServerVerification,
  asTcbInfo,
  isRecord,
} from "./schema";
import type {
  CollateralBundle,
  CollateralStatus,
  CryptographicVerificationStatus,
  NormalizedAttestationReport,
  VerificationMode,
} from "./types";

type VerificationAnalysis = {
  checks: CheckResult[];
  collateralStatus: CollateralStatus;
  cryptographicStatus: CryptographicVerificationStatus;
  derivedSigningAddress?: string;
  mode: VerificationMode;
  quoteReportData?: string;
  verifiedAt?: string;
};

const TDX_BODY_OFFSET = 48;
const TDX_REPORT_BODY_LENGTH = 584;
const TDX_SIGNATURE_LENGTH_OFFSET = TDX_BODY_OFFSET + TDX_REPORT_BODY_LENGTH;
const TDX_SIG_DATA_OFFSET = TDX_SIGNATURE_LENGTH_OFFSET + 4;
const TDX_FIELD_LAYOUT = {
  mrConfigId: { offset: 184, length: 48 },
  mrOwner: { offset: 64, length: 48 },
  mrOwnerConfig: { offset: 112, length: 48 },
  mrtd: { offset: 136, length: 48 },
  reportData: { offset: 520, length: 64 },
  rtmr0: { offset: 328, length: 48 },
  rtmr1: { offset: 376, length: 48 },
  rtmr2: { offset: 424, length: 48 },
  rtmr3: { offset: 472, length: 48 },
  tdAttributes: { offset: 120, length: 8 },
  xfam: { offset: 128, length: 8 },
} as const;

const TDX_QUOTE_SIGNATURE_LENGTH = 64;
const TDX_ATTESTATION_KEY_LENGTH = 64;
const TDX_QE_REPORT_PADDING_LENGTH = 6;
const TDX_QE_REPORT_LENGTH = 384;
const TDX_QE_REPORT_SIGNATURE_LENGTH = 64;
const TDX_QE_REPORT_REPORT_DATA_OFFSET = 320;
const TDX_QE_REPORT_REPORT_DATA_LENGTH = 64;

type DecodedQuote = {
  attestationPublicKey?: Uint8Array;
  certificationData?: string;
  certificationDataType?: number;
  mrConfigId: string;
  mrOwner: string;
  mrOwnerConfig: string;
  mrtd: string;
  qeAuthData?: Uint8Array;
  qeReport?: Uint8Array;
  qeReportSignature?: Uint8Array;
  quoteBytes: Uint8Array;
  quoteReportData: string;
  quoteSignature?: Uint8Array;
  reportData: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  tdAttributes: string;
  version: number;
  xfam: string;
};

export async function verifyNormalizedReport(
  report: NormalizedAttestationReport,
  collateralBundle?: CollateralBundle,
): Promise<VerificationAnalysis> {
  const checks: CheckResult[] = [];
  let derivedSigningAddress: string | undefined;
  let quoteReportData: string | undefined;
  let verifiedAt: string | undefined;
  let mode: VerificationMode = "offline";
  let collateralStatus: CollateralStatus = collateralBundle ? "provided" : "not-requested";
  let cryptographicStatus: CryptographicVerificationStatus = "unsupported";
  let hasLocalCryptoPass = false;
  let hasFullCryptoPass = false;

  const publicKey = normalizeHex(report.signing_public_key);
  const signingKey = normalizeHex(report.signing_key);
  const reportedAddress = normalizeAddress(report.signing_address);
  const nonce = normalizeHex(report.nonce);
  const requestNonce = normalizeHex(report.request_nonce);

  if (publicKey && publicKey.length === 130 && publicKey.startsWith("04")) {
    derivedSigningAddress = deriveEthereumAddress(publicKey);

    checks.push(
      buildCheck({
        description:
          reportedAddress && derivedSigningAddress === reportedAddress
            ? "The signing public key derives to the reported Ethereum address."
            : "The signing public key does not derive to the reported signing address.",
        domain: "binding",
        id: "signing-address-binding",
        jsonPath: "$.signing_public_key",
        label: "Verify signing public key binding",
        severity: "blocking",
        source: "local",
        status:
          reportedAddress && derivedSigningAddress === reportedAddress
            ? "pass"
            : "fail",
      }),
    );
  } else {
    checks.push(
      buildCheck({
        description:
          "The signing public key is missing or not a 65-byte uncompressed secp256k1 public key.",
        domain: "binding",
        id: "signing-address-binding",
        jsonPath: "$.signing_public_key",
        label: "Verify signing public key binding",
        severity: "blocking",
        source: "local",
        status: "fail",
      }),
    );
  }

  checks.push(
    buildCheck({
      description:
        publicKey && signingKey && publicKey.toLowerCase() === signingKey.toLowerCase()
          ? "The duplicated signing key fields agree."
          : "The signing key fields disagree or one is missing.",
      domain: "binding",
      id: "signing-key-consistency",
      jsonPath: "$.signing_key",
      label: "Check signing key consistency",
      severity: "blocking",
      source: "local",
      status:
        publicKey && signingKey && publicKey.toLowerCase() === signingKey.toLowerCase()
          ? "pass"
          : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description:
        nonce && requestNonce && nonce === requestNonce
          ? "The top-level nonce matches the request nonce."
          : "The top-level nonce does not match the request nonce.",
      domain: "binding",
      id: "request-nonce-consistency",
      jsonPath: "$.nonce",
      label: "Check top-level nonce binding",
      severity: "blocking",
      source: "local",
      status: nonce && requestNonce && nonce === requestNonce ? "pass" : "fail",
    }),
  );

  const nvidiaNonce = normalizeHex(report.nvidia_payload.nonce);

  checks.push(
    buildCheck({
      description:
        nonce && nvidiaNonce && nonce === nvidiaNonce
          ? "The NVIDIA payload nonce matches the attestation nonce."
          : "The NVIDIA payload nonce does not match the attestation nonce.",
      domain: "binding",
      id: "nvidia-nonce-binding",
      jsonPath: "$.nvidia_payload.nonce",
      label: "Check NVIDIA nonce binding",
      severity: "blocking",
      source: "local",
      status: nonce && nvidiaNonce && nonce === nvidiaNonce ? "pass" : "fail",
    }),
  );

  const evidenceList = Array.isArray(report.nvidia_payload.evidence_list)
    ? report.nvidia_payload.evidence_list
    : [];

  checks.push(
    buildCheck({
      description:
        evidenceList.length > 0
          ? `The NVIDIA payload includes ${evidenceList.length} evidence entries with certificate and evidence blobs.`
          : "The NVIDIA payload is missing its evidence list.",
      domain: "nvidia",
      id: "nvidia-evidence-shape",
      jsonPath: "$.nvidia_payload.evidence_list",
      label: "Inspect NVIDIA evidence bundle",
      severity: "blocking",
      source: "local",
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
    }),
  );

  if (typeof report.info.app_cert === "string" && report.info.app_cert.length > 0) {
    const appCertResult = await validateCertificateChain({
      bundle: report.info.app_cert,
      bundleLabel: "App certificate bundle",
      domain: "app",
      jsonPath: "$.info.app_cert",
    });

    checks.push(...appCertResult.checks);

    if (appCertResult.fetchedCollateral) {
      mode = "online";
      collateralStatus = "fetched";
    } else if (collateralStatus === "not-requested") {
      collateralStatus = "missing";
    }
  } else {
    checks.push(
      buildCheck({
        description: "The info block is missing the app certificate bundle.",
        domain: "app-cert",
        id: "app-certificate-bundle",
        jsonPath: "$.info.app_cert",
        label: "Inspect app certificate bundle",
        severity: "blocking",
        source: "local",
        status: "fail",
      }),
    );
  }

  const quote = decodeTdxQuote(report.intel_quote);

  if (quote) {
    quoteReportData = quote.reportData;

    checks.push(
      buildCheck({
        description:
          quote.version === 4
            ? "The Intel quote decoded successfully as a TDX v4 quote."
            : `The Intel quote decoded successfully with unsupported version ${quote.version}.`,
        domain: "tdx",
        id: "tdx-quote-shape",
        jsonPath: "$.intel_quote",
        label: "Decode Intel TDX quote",
        severity: "blocking",
        source: "local",
        status: quote.version === 4 ? "pass" : "fail",
      }),
    );

    const expectedReportData =
      reportedAddress && nonce
        ? `${reportedAddress.slice(2).toLowerCase()}${"0".repeat(24)}${nonce}`
        : undefined;

    checks.push(
      buildCheck({
        description:
          expectedReportData && quote.reportData === expectedReportData
            ? "The quote report data binds the signing address and nonce exactly as expected."
            : "The quote report data does not match the expected address-plus-nonce binding.",
        domain: "binding",
        id: "tdx-report-data-binding",
        jsonPath: "$.intel_quote",
        label: "Check TDX quote report data",
        severity: "blocking",
        source: "local",
        status:
          expectedReportData && quote.reportData === expectedReportData
            ? "pass"
            : "fail",
      }),
    );

    checks.push(...buildMeasurementChecks({ quote, report }));

    const tdxCryptoResult = await verifyTdxQuoteCryptography({
      collateralBundle,
      quote,
    });
    checks.push(...tdxCryptoResult.checks);

    if (tdxCryptoResult.fetchedCollateral) {
      mode = "online";
      collateralStatus = "fetched";
    } else if (collateralBundle?.intel && collateralStatus !== "fetched") {
      collateralStatus = "provided";
    } else if (collateralStatus === "not-requested") {
      collateralStatus = "missing";
    }

    hasLocalCryptoPass ||= tdxCryptoResult.localCryptoPass;
  } else {
    checks.push(
      buildCheck({
        description:
          "The Intel quote is missing, malformed, or too short to decode its measurements and report data.",
        domain: "tdx",
        id: "tdx-quote-shape",
        jsonPath: "$.intel_quote",
        label: "Decode Intel TDX quote",
        severity: "blocking",
        source: "local",
        status: "fail",
      }),
    );
  }

  const nvidiaCryptoResult = await verifyNvidiaEvidence({
    collateralBundle,
    evidenceList,
  });
  checks.push(...nvidiaCryptoResult.checks);

  if (nvidiaCryptoResult.fetchedCollateral) {
    mode = "online";
    collateralStatus = "fetched";
  } else if (collateralBundle?.nvidia && collateralStatus !== "fetched") {
    collateralStatus = "provided";
  } else if (collateralStatus === "not-requested") {
    collateralStatus = "missing";
  }

  hasLocalCryptoPass ||= nvidiaCryptoResult.localCryptoPass;
  hasFullCryptoPass ||= nvidiaCryptoResult.fullCryptoPass;

  checks.push(...buildEventLogChecks(report));
  checks.push(...buildKeyProviderChecks(report));

  const serverClaims = evaluateEmbeddedClaims(report, derivedSigningAddress);
  checks.push(...serverClaims.checks);
  verifiedAt = serverClaims.verifiedAt;

  if (hasFullCryptoPass) {
    cryptographicStatus = "verified";
  } else if (hasLocalCryptoPass) {
    cryptographicStatus = "partial";
  }

  return {
    checks,
    collateralStatus,
    cryptographicStatus,
    derivedSigningAddress,
    mode,
    quoteReportData,
    verifiedAt,
  };
}

function buildMeasurementChecks({
  quote,
  report,
}: {
  quote: DecodedQuote;
  report: NormalizedAttestationReport;
}): CheckResult[] {
  const checks: CheckResult[] = [];
  const info = asInfoBlock(report.info);
  const tcbInfo = asTcbInfo(info?.tcb_info);
  const composeHash = normalizeHex(info?.compose_hash);

  checks.push(
    buildCheck({
      description:
        normalizeHex(tcbInfo?.mrtd) && quote.mrtd === normalizeHex(tcbInfo?.mrtd)
          ? "The quote MR TD matches the reported TCB info."
          : "The quote MR TD does not match the reported TCB info.",
      domain: "tdx",
      id: "tdx-mrtd",
      jsonPath: "$.info.tcb_info.mrtd",
      label: "Check TDX measurement: MR TD",
      severity: "blocking",
      source: "local",
      status:
        normalizeHex(tcbInfo?.mrtd) && quote.mrtd === normalizeHex(tcbInfo?.mrtd)
          ? "pass"
          : "fail",
    }),
  );

  for (const rtmr of ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] as const) {
    const expected = normalizeHex(tcbInfo?.[rtmr]);
    const actual = quote[rtmr];

    checks.push(
      buildCheck({
        description:
          expected && actual === expected
            ? `${rtmr.toUpperCase()} matches the reported TCB info.`
            : `${rtmr.toUpperCase()} does not match the reported TCB info.`,
        domain: "tdx",
        id: `tdx-${rtmr}`,
        jsonPath: `$.info.tcb_info.${rtmr}`,
        label: `Check TDX measurement: ${rtmr.toUpperCase()}`,
        severity: "blocking",
        source: "local",
        status: expected && actual === expected ? "pass" : "fail",
      }),
    );
  }

  checks.push(
    buildCheck({
      description:
        composeHash &&
        quote.mrConfigId.length >= 66 &&
        quote.mrConfigId.slice(2, 66) === composeHash
          ? "The quote MRCONFIGID embeds the reported compose hash."
          : "The quote MRCONFIGID does not embed the reported compose hash.",
      domain: "tdx",
      id: "tdx-compose-hash",
      jsonPath: "$.info.compose_hash",
      label: "Check quote MRCONFIGID against compose hash",
      severity: "blocking",
      source: "local",
      status:
        composeHash &&
        quote.mrConfigId.length >= 66 &&
        quote.mrConfigId.slice(2, 66) === composeHash
          ? "pass"
          : "fail",
    }),
  );

  return checks;
}

function buildEventLogChecks(report: NormalizedAttestationReport): CheckResult[] {
  const eventMap = collectNamedEventPayloads(report.event_log);
  const info = asInfoBlock(report.info);
  const tcbInfo = asTcbInfo(info?.tcb_info);
  const checks: CheckResult[] = [];

  checks.push(
    buildCheck({
      description:
        normalizeHex(eventMap["app-id"]) &&
        normalizeHex(info?.app_id) &&
        normalizeHex(eventMap["app-id"]) === normalizeHex(info?.app_id)
          ? "The event log app-id matches the info block."
          : "The event log app-id does not match the info block.",
      domain: "event-log",
      id: "event-log-app-id",
      jsonPath: "$.event_log",
      label: "Check event log app ID binding",
      severity: "blocking",
      source: "local",
      status:
        normalizeHex(eventMap["app-id"]) &&
        normalizeHex(info?.app_id) &&
        normalizeHex(eventMap["app-id"]) === normalizeHex(info?.app_id)
          ? "pass"
          : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description:
        normalizeHex(eventMap["compose-hash"]) &&
        normalizeHex(info?.compose_hash) &&
        normalizeHex(eventMap["compose-hash"]) === normalizeHex(info?.compose_hash)
          ? "The event log compose hash matches the info block."
          : "The event log compose hash does not match the info block.",
      domain: "event-log",
      id: "event-log-compose-hash",
      jsonPath: "$.event_log",
      label: "Check event log compose hash binding",
      severity: "blocking",
      source: "local",
      status:
        normalizeHex(eventMap["compose-hash"]) &&
        normalizeHex(info?.compose_hash) &&
        normalizeHex(eventMap["compose-hash"]) === normalizeHex(info?.compose_hash)
          ? "pass"
          : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description:
        normalizeHex(eventMap["instance-id"]) &&
        normalizeHex(info?.instance_id) &&
        normalizeHex(eventMap["instance-id"]) === normalizeHex(info?.instance_id)
          ? "The event log instance-id matches the info block."
          : "The event log instance-id does not match the info block.",
      domain: "event-log",
      id: "event-log-instance-id",
      jsonPath: "$.event_log",
      label: "Check event log instance ID binding",
      severity: "blocking",
      source: "local",
      status:
        normalizeHex(eventMap["instance-id"]) &&
        normalizeHex(info?.instance_id) &&
        normalizeHex(eventMap["instance-id"]) === normalizeHex(info?.instance_id)
          ? "pass"
          : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description:
        normalizeHex(eventMap["os-image-hash"]) &&
        normalizeHex(tcbInfo?.os_image_hash) &&
        normalizeHex(eventMap["os-image-hash"]) ===
          normalizeHex(tcbInfo?.os_image_hash)
          ? "The event log OS image hash matches the TCB info."
          : "The event log OS image hash does not match the TCB info.",
      domain: "event-log",
      id: "event-log-os-image-hash",
      jsonPath: "$.event_log",
      label: "Check event log OS image hash binding",
      severity: "blocking",
      source: "local",
      status:
        normalizeHex(eventMap["os-image-hash"]) &&
        normalizeHex(tcbInfo?.os_image_hash) &&
        normalizeHex(eventMap["os-image-hash"]) ===
          normalizeHex(tcbInfo?.os_image_hash)
          ? "pass"
          : "fail",
    }),
  );

  if (Array.isArray(report.event_log) && Array.isArray(tcbInfo?.event_log)) {
    checks.push(
      buildCheck({
        description:
          JSON.stringify(report.event_log) === JSON.stringify(tcbInfo.event_log)
            ? "The top-level event log matches the copy embedded in the TCB info."
            : "The top-level event log differs from the copy embedded in the TCB info.",
        domain: "event-log",
        id: "event-log-duplication",
        jsonPath: "$.info.tcb_info.event_log",
        label: "Check duplicated event log consistency",
        severity: "blocking",
        source: "local",
        status:
          JSON.stringify(report.event_log) === JSON.stringify(tcbInfo.event_log)
            ? "pass"
            : "fail",
      }),
    );
  }

  return checks;
}

function buildKeyProviderChecks(report: NormalizedAttestationReport): CheckResult[] {
  const info = asInfoBlock(report.info);
  const eventMap = collectNamedEventPayloads(report.event_log);
  const encodedKeyProviderPayload = normalizeHex(eventMap["key-provider"]);
  const checks: CheckResult[] = [];

  const infoKeyProvider = parseJsonObject(info?.key_provider_info);
  const eventKeyProvider =
    encodedKeyProviderPayload !== undefined
      ? parseJsonObject(hexToUtf8(encodedKeyProviderPayload))
      : undefined;

  checks.push(
    buildCheck({
      description:
        infoKeyProvider &&
        eventKeyProvider &&
        JSON.stringify(infoKeyProvider) === JSON.stringify(eventKeyProvider)
          ? "The key provider metadata matches between the info block and event log."
          : "The key provider metadata does not match between the info block and event log.",
      domain: "event-log",
      id: "key-provider-binding",
      jsonPath: "$.info.key_provider_info",
      label: "Check key provider metadata binding",
      severity: "blocking",
      source: "local",
      status:
        infoKeyProvider &&
        eventKeyProvider &&
        JSON.stringify(infoKeyProvider) === JSON.stringify(eventKeyProvider)
          ? "pass"
          : "fail",
    }),
  );

  return checks;
}

async function verifyTdxQuoteCryptography({
  collateralBundle,
  quote,
}: {
  collateralBundle?: CollateralBundle;
  quote: DecodedQuote;
}): Promise<{
  checks: CheckResult[];
  fetchedCollateral: boolean;
  localCryptoPass: boolean;
}> {
  const checks: CheckResult[] = [];

  if (
    !quote.attestationPublicKey ||
    !quote.quoteSignature ||
    !quote.qeReport ||
    !quote.qeReportSignature ||
    !quote.qeAuthData ||
    !quote.certificationData
  ) {
    checks.push(
      buildCheck({
        description:
          "The TDX quote is missing attestation key, QE report, signature, or certification data fields required for local cryptographic verification.",
        domain: "tdx",
        id: "tdx-local-crypto-support",
        jsonPath: "$.intel_quote",
        label: "Inspect TDX local crypto inputs",
        severity: "blocking",
        source: "local",
        status: "fail",
      }),
    );

    return {
      checks,
      fetchedCollateral: false,
      localCryptoPass: false,
    };
  }

  checks.push(
    buildCheck({
      description:
        quote.certificationDataType === 5
          ? "The quote includes an Intel PCK certificate chain in certification data type 5."
          : `The quote includes unsupported certification data type ${String(
              quote.certificationDataType,
            )}.`,
      domain: "tdx",
      id: "tdx-certification-data",
      jsonPath: "$.intel_quote",
      label: "Inspect quote certification data",
      severity: "blocking",
      source: "local",
      status: quote.certificationDataType === 5 ? "pass" : "fail",
    }),
  );

  const chainResult = await validateCertificateChain({
    bundle: quote.certificationData,
    bundleLabel: "Intel PCK certificate chain",
    collateralCrlPem: collateralBundle?.intel?.pckCrl,
    domain: "intel",
    jsonPath: "$.intel_quote",
  });

  checks.push(...chainResult.checks);

  const localQuoteSignatureValid = await verifyP256Signature({
    payload: quote.quoteBytes.slice(0, TDX_SIGNATURE_LENGTH_OFFSET),
    publicKey: quote.attestationPublicKey,
    signature: quote.quoteSignature,
  });

  checks.push(
    buildCheck({
      description: localQuoteSignatureValid
        ? "The quote signature validates against the embedded attestation public key."
        : "The quote signature does not validate against the embedded attestation public key.",
      domain: "tdx",
      id: "tdx-quote-signature",
      jsonPath: "$.intel_quote",
      label: "Verify TDX quote signature",
      severity: "blocking",
      source: "local",
      status: localQuoteSignatureValid ? "pass" : "fail",
    }),
  );

  let qeReportSignatureValid = false;
  if (chainResult.chain?.[0]) {
    const pckPublicKey = await chainResult.chain[0].publicKey.export(
      { name: "ECDSA", namedCurve: "P-256" },
      ["verify"],
    );
    qeReportSignatureValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pckPublicKey,
      toArrayBuffer(quote.qeReportSignature),
      toArrayBuffer(quote.qeReport),
    );
  }

  checks.push(
    buildCheck({
      description: qeReportSignatureValid
        ? "The QE report signature validates against the Intel PCK leaf certificate."
        : "The QE report signature does not validate against the Intel PCK leaf certificate.",
      domain: "tdx",
      id: "tdx-qe-report-signature",
      jsonPath: "$.intel_quote",
      label: "Verify QE report signature",
      severity: "blocking",
      source: "local",
      status: qeReportSignatureValid ? "pass" : "fail",
    }),
  );

  const expectedQeReportData = sha256Hex(
    concatBytes(quote.attestationPublicKey, quote.qeAuthData),
  );
  const actualQeReportData = bytesToHex(
    quote.qeReport.slice(
      TDX_QE_REPORT_REPORT_DATA_OFFSET,
      TDX_QE_REPORT_REPORT_DATA_OFFSET + TDX_QE_REPORT_REPORT_DATA_LENGTH,
    ),
  ).slice(2);

  const qeReportDataMatches =
    actualQeReportData.slice(0, expectedQeReportData.length) ===
      expectedQeReportData &&
    /^0*$/.test(actualQeReportData.slice(expectedQeReportData.length));

  checks.push(
    buildCheck({
      description: qeReportDataMatches
        ? "The QE report data commits to the attestation public key and QE auth data."
        : "The QE report data does not match the attestation public key plus QE auth data hash.",
      domain: "tdx",
      id: "tdx-qe-report-data",
      jsonPath: "$.intel_quote",
      label: "Check QE report data binding",
      severity: "blocking",
      source: "local",
      status: qeReportDataMatches ? "pass" : "fail",
    }),
  );

  const missingCollateral =
    collateralBundle?.intel?.qeIdentity === undefined ||
    collateralBundle?.intel?.tcbInfo === undefined;

  checks.push(
    buildCheck({
      description: missingCollateral
        ? "Intel QE identity and TCB collateral were not supplied, so TDX collateral validation remains partial."
        : "Intel QE identity and TCB collateral were supplied for follow-on verification.",
      domain: "collateral",
      id: "tdx-collateral-availability",
      jsonPath: "$.intel_quote",
      label: "Inspect Intel collateral availability",
      severity: "advisory",
      source: collateralBundle?.intel ? "local" : "online-collateral",
      status: missingCollateral ? "info" : "pass",
    }),
  );

  return {
    checks,
    fetchedCollateral: chainResult.fetchedCollateral,
    localCryptoPass:
      localQuoteSignatureValid &&
      qeReportSignatureValid &&
      qeReportDataMatches &&
      !chainResult.checks.some(
        (check) => check.severity === "blocking" && check.status === "fail",
      ),
  };
}

async function verifyNvidiaEvidence({
  collateralBundle,
  evidenceList,
}: {
  collateralBundle?: CollateralBundle;
  evidenceList: NormalizedAttestationReport["nvidia_payload"]["evidence_list"];
}): Promise<{
  checks: CheckResult[];
  fetchedCollateral: boolean;
  fullCryptoPass: boolean;
  localCryptoPass: boolean;
}> {
  const checks: CheckResult[] = [];

  if (evidenceList.length === 0) {
    return {
      checks,
      fetchedCollateral: false,
      fullCryptoPass: false,
      localCryptoPass: false,
    };
  }

  let fetchedCollateral = false;
  let certificateChainsPassed = true;

  for (const [index, entry] of evidenceList.entries()) {
    const certificatePem = decodeBase64Utf8(entry.certificate);
    const chainResult = await validateCertificateChain({
      bundle: certificatePem,
      bundleLabel: `NVIDIA certificate chain ${index + 1}`,
      collateralCrlPem: collateralBundle?.nvidia?.crls?.[index],
      domain: "nvidia",
      jsonPath: `$.nvidia_payload.evidence_list[${index}].certificate`,
    });

    checks.push(...chainResult.checks);
    fetchedCollateral ||= chainResult.fetchedCollateral;
    certificateChainsPassed &&=
      !chainResult.checks.some(
        (check) => check.severity === "blocking" && check.status === "fail",
      );

    checks.push(
      buildCheck({
        description:
          normalizeBase64(entry.evidence) !== undefined
            ? "The NVIDIA evidence blob is present and decodes from base64."
            : "The NVIDIA evidence blob is missing or not valid base64.",
        domain: "nvidia",
        id: `nvidia-evidence-base64-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].evidence`,
        label: "Decode NVIDIA evidence blob",
        severity: "blocking",
        source: "local",
        status: normalizeBase64(entry.evidence) !== undefined ? "pass" : "fail",
      }),
    );
  }

  checks.push(
    buildCheck({
      description:
        "This build validates NVIDIA certificate chains but does not yet re-derive raw NVIDIA evidence signatures from the opaque evidence blob format.",
      domain: "nvidia",
      id: "nvidia-raw-evidence-unsupported",
      jsonPath: "$.nvidia_payload.evidence_list",
      label: "Inspect NVIDIA raw evidence support",
      severity: "advisory",
      source: "local",
      status: "info",
    }),
  );

  return {
    checks,
    fetchedCollateral,
    fullCryptoPass: false,
    localCryptoPass: certificateChainsPassed,
  };
}

function evaluateEmbeddedClaims(
  report: NormalizedAttestationReport,
  derivedSigningAddress?: string,
): {
  checks: CheckResult[];
  verifiedAt?: string;
} {
  const checks: CheckResult[] = [];
  const serverVerification = asServerVerification(report.server_verification);

  if (!serverVerification) {
    checks.push(
      buildCheck({
        description:
          "No embedded server verification block was present. Embedded claims are optional provenance only and do not control the verdict.",
        domain: "collateral",
        id: "embedded-verification-claims",
        jsonPath: "$.server_verification",
        label: "Inspect embedded verification claims",
        severity: "advisory",
        source: "embedded",
        status: "info",
      }),
    );

    return { checks };
  }

  const tdx = isRecord(serverVerification.tdx) ? serverVerification.tdx : undefined;
  const nvidia = isRecord(serverVerification.nvidia)
    ? serverVerification.nvidia
    : undefined;
  const verifiedAt =
    typeof serverVerification.verifiedAt === "string"
      ? serverVerification.verifiedAt
      : undefined;

  checks.push(
    buildCheck({
      description:
        report.verified === true
          ? "The report includes an embedded verified flag from an upstream verifier."
          : "The report does not include an embedded verified flag.",
      domain: "collateral",
      id: "embedded-report-verified-flag",
      jsonPath: "$.verified",
      label: "Inspect embedded verified flag",
      severity: "advisory",
      source: "embedded",
      status: report.verified === true ? "pass" : "info",
    }),
  );

  checks.push(
    buildCheck({
      description:
        tdx?.valid === true
          ? "The embedded verifier reports a valid TDX quote."
          : "The embedded verifier does not report a valid TDX quote.",
      domain: "tdx",
      id: "embedded-tdx-claims",
      jsonPath: "$.server_verification.tdx",
      label: "Inspect embedded TDX verification claims",
      severity: "advisory",
      source: "embedded",
      status: tdx?.valid === true ? "pass" : "info",
    }),
  );

  checks.push(
    buildCheck({
      description:
        nvidia?.valid === true
          ? "The embedded verifier reports valid NVIDIA evidence."
          : "The embedded verifier does not report valid NVIDIA evidence.",
      domain: "nvidia",
      id: "embedded-nvidia-claims",
      jsonPath: "$.server_verification.nvidia",
      label: "Inspect embedded NVIDIA verification claims",
      severity: "advisory",
      source: "embedded",
      status: nvidia?.valid === true ? "pass" : "info",
    }),
  );

  const embeddedAddress = normalizeAddress(
    isRecord(serverVerification.signingAddressBinding)
      ? serverVerification.signingAddressBinding.reportDataAddress
      : undefined,
  );

  checks.push(
    buildCheck({
      description:
        embeddedAddress !== undefined && embeddedAddress === derivedSigningAddress
          ? "The embedded verifier reports the same signing address binding derived locally."
          : "The embedded verifier does not provide a matching signing address binding.",
      domain: "binding",
      id: "embedded-binding-claims",
      jsonPath: "$.server_verification",
      label: "Inspect embedded binding claims",
      severity: "advisory",
      source: "embedded",
      status:
        embeddedAddress !== undefined && embeddedAddress === derivedSigningAddress
          ? "pass"
          : "info",
    }),
  );

  return {
    checks,
    verifiedAt,
  };
}

function decodeTdxQuote(value: unknown): DecodedQuote | undefined {
  const quoteHex = normalizeHex(value);
  if (!quoteHex) {
    return undefined;
  }

  try {
    const quoteBytes = hexToBytes(`0x${quoteHex}`);
    if (quoteBytes.length < TDX_SIG_DATA_OFFSET) {
      return undefined;
    }

    const view = new DataView(
      quoteBytes.buffer,
      quoteBytes.byteOffset,
      quoteBytes.byteLength,
    );
    const signatureDataLength = view.getUint32(TDX_SIGNATURE_LENGTH_OFFSET, true);
    if (quoteBytes.length < TDX_SIG_DATA_OFFSET + signatureDataLength) {
      return undefined;
    }

    const signatureData = quoteBytes.slice(
      TDX_SIG_DATA_OFFSET,
      TDX_SIG_DATA_OFFSET + signatureDataLength,
    );

    const quoteSignature = signatureData.slice(0, TDX_QUOTE_SIGNATURE_LENGTH);
    const attestationPublicKey = signatureData.slice(
      TDX_QUOTE_SIGNATURE_LENGTH,
      TDX_QUOTE_SIGNATURE_LENGTH + TDX_ATTESTATION_KEY_LENGTH,
    );
    const qeReportStart =
      TDX_QUOTE_SIGNATURE_LENGTH +
      TDX_ATTESTATION_KEY_LENGTH +
      TDX_QE_REPORT_PADDING_LENGTH;
    const qeReport = signatureData.slice(
      qeReportStart,
      qeReportStart + TDX_QE_REPORT_LENGTH,
    );
    const qeReportSignatureOffset = qeReportStart + TDX_QE_REPORT_LENGTH;
    const qeReportSignature = signatureData.slice(
      qeReportSignatureOffset,
      qeReportSignatureOffset + TDX_QE_REPORT_SIGNATURE_LENGTH,
    );
    const authSizeOffset = qeReportSignatureOffset + TDX_QE_REPORT_SIGNATURE_LENGTH;
    const authSize = new DataView(
      signatureData.buffer,
      signatureData.byteOffset,
      signatureData.byteLength,
    ).getUint16(authSizeOffset, true);
    const authDataOffset = authSizeOffset + 2;
    const authData = signatureData.slice(authDataOffset, authDataOffset + authSize);
    const certificationHeaderOffset = authDataOffset + authSize;
    const certificationDataType = new DataView(
      signatureData.buffer,
      signatureData.byteOffset,
      signatureData.byteLength,
    ).getUint16(certificationHeaderOffset, true);
    const certificationDataSize = new DataView(
      signatureData.buffer,
      signatureData.byteOffset,
      signatureData.byteLength,
    ).getUint32(certificationHeaderOffset + 2, true);
    const certificationData = signatureData.slice(
      certificationHeaderOffset + 6,
      certificationHeaderOffset + 6 + certificationDataSize,
    );

    return {
      attestationPublicKey,
      certificationData: new TextDecoder().decode(certificationData),
      certificationDataType,
      mrConfigId: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrConfigId.offset,
        48,
      ),
      mrOwner: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.mrOwner.offset, 48),
      mrOwnerConfig: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrOwnerConfig.offset,
        48,
      ),
      mrtd: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.mrtd.offset, 48),
      qeAuthData: authData,
      qeReport,
      qeReportSignature,
      quoteBytes,
      quoteReportData: bytesToHex(
        qeReport.slice(
          TDX_QE_REPORT_REPORT_DATA_OFFSET,
          TDX_QE_REPORT_REPORT_DATA_OFFSET + TDX_QE_REPORT_REPORT_DATA_LENGTH,
        ),
      ).slice(2),
      quoteSignature,
      reportData: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.reportData.offset, 64),
      rtmr0: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.rtmr0.offset, 48),
      rtmr1: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.rtmr1.offset, 48),
      rtmr2: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.rtmr2.offset, 48),
      rtmr3: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.rtmr3.offset, 48),
      tdAttributes: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.tdAttributes.offset,
        8,
      ),
      version: view.getUint16(0, true),
      xfam: extractQuoteField(quoteBytes, TDX_FIELD_LAYOUT.xfam.offset, 8),
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

function collectNamedEventPayloads(
  value: NormalizedAttestationReport["event_log"],
): Record<string, string> {
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

function normalizeBase64(value: unknown): Uint8Array | undefined {
  if (typeof value !== "string" || value.trim().length === 0) {
    return undefined;
  }

  try {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
}

function decodeBase64Utf8(value: string): string {
  const bytes = normalizeBase64(value);
  if (!bytes) {
    return "";
  }

  return new TextDecoder().decode(bytes);
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

async function verifyP256Signature({
  payload,
  publicKey,
  signature,
}: {
  payload: Uint8Array;
  publicKey: Uint8Array;
  signature: Uint8Array;
}): Promise<boolean> {
  try {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(concatBytes(new Uint8Array([4]), publicKey)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      toArrayBuffer(signature),
      toArrayBuffer(payload),
    );
  } catch {
    return false;
  }
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength,
  ) as ArrayBuffer;
}

function buildCheck({
  description,
  domain,
  id,
  jsonPath,
  label,
  severity,
  source,
  status,
}: CheckResult): CheckResult {
  return {
    description,
    domain,
    id,
    jsonPath,
    label,
    severity,
    source,
    status,
  };
}
