import { bytesToHex, getAddress, hexToBytes, keccak256 } from "viem";
import type { CheckDetail, CheckResult } from "./check-result";
import { parseDerAt } from "./asn1";
import { validateCertificateChain } from "./certificates";
import {
  concatBytes,
  sha256Hex,
  toArrayBuffer,
  toHex,
  verifyEcdsaSignature,
} from "./crypto";
import {
  evaluateQeIdentity,
  evaluateTcbInfo,
  isCollateralCurrent,
  parseIntelPckExtensions,
  parseQeReport,
  verifyIntelCollateralSignature,
} from "./intel";
import {
  parseNvidiaEvidence,
  normalizeNvidiaArchitecture,
  verifyNvidiaEvidenceSignature,
} from "./nvidia";
import {
  asInfoBlock,
  asIntelSignedQeIdentity,
  asIntelSignedTcbInfo,
  asServerVerification,
  asTcbInfo,
  isRecord,
} from "./schema";
import type {
  CryptographicVerificationStatus,
  EvidenceVerificationStatus,
  IntelSignedQeIdentity,
  IntelSignedTcbInfo,
  NormalizedAttestationReport,
  VerificationMode,
} from "./types";

type VerificationAnalysis = {
  checks: CheckResult[];
  cryptographicStatus: CryptographicVerificationStatus;
  derivedSigningAddress?: string;
  evidenceStatus: {
    intel: EvidenceVerificationStatus;
    nvidia: EvidenceVerificationStatus;
  };
  mode: VerificationMode;
  quoteReportData?: string;
  verifiedAt?: string;
};

type DomainVerificationResult = {
  checks: CheckResult[];
  status: EvidenceVerificationStatus;
};

type TdxCryptographyResult = {
  baseCryptoPassed: boolean;
  checks: CheckResult[];
  pckExtensions?: ReturnType<typeof parseIntelPckExtensions>;
  qeReport?: ReturnType<typeof parseQeReport>;
};

const TDX_HEADER_LENGTH = 48;
const TDX_REPORT_BODY_LENGTH = 584;
const TDX_AUTH_DATA_LENGTH_OFFSET = TDX_HEADER_LENGTH + TDX_REPORT_BODY_LENGTH;
const TDX_AUTH_DATA_OFFSET = TDX_AUTH_DATA_LENGTH_OFFSET + 4;
const TDX_FIELD_LAYOUT = {
  mrConfigId: { length: 48, offset: 184 },
  mrOwner: { length: 48, offset: 232 },
  mrOwnerConfig: { length: 48, offset: 280 },
  mrSeam: { length: 48, offset: 16 },
  mrSignerSeam: { length: 48, offset: 64 },
  mrtd: { length: 48, offset: 136 },
  reportData: { length: 64, offset: 520 },
  rtmr0: { length: 48, offset: 328 },
  rtmr1: { length: 48, offset: 376 },
  rtmr2: { length: 48, offset: 424 },
  rtmr3: { length: 48, offset: 472 },
  seamAttributes: { length: 8, offset: 112 },
  tdAttributes: { length: 8, offset: 120 },
  teeTcbSvn: { length: 16, offset: 0 },
  xfam: { length: 8, offset: 128 },
} as const;

const TDX_QUOTE_SIGNATURE_LENGTH = 64;
const TDX_ATTESTATION_KEY_LENGTH = 64;
const TDX_QE_REPORT_LENGTH = 384;
const TDX_QE_REPORT_SIGNATURE_LENGTH = 64;
const TDX_QE_REPORT_REPORT_DATA_OFFSET = 320;
const TDX_QE_REPORT_REPORT_DATA_LENGTH = 64;
const TDX_QE_REPORT_CERTIFICATION_DATA_TYPE = 6;
const TDX_PCK_CERT_CHAIN_CERTIFICATION_DATA_TYPE = 5;

type DecodedQuote = {
  attestationPublicKey?: Uint8Array;
  certificationData?: string;
  certificationDataType?: number;
  mrConfigId: string;
  mrOwner: string;
  mrOwnerConfig: string;
  mrSeam: string;
  mrSignerSeam: string;
  mrtd: string;
  outerCertificationDataType?: number;
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
  seamAttributes: string;
  tdAttributes: string;
  teeTcbSvn: number[];
  version: number;
  xfam: string;
};

export async function verifyNormalizedReport(
  report: NormalizedAttestationReport,
): Promise<VerificationAnalysis> {
  const checks: CheckResult[] = [];
  let derivedSigningAddress: string | undefined;
  let quoteReportData: string | undefined;
  let verifiedAt: string | undefined;

  const evidenceStatus: VerificationAnalysis["evidenceStatus"] = {
    intel: "unsupported",
    nvidia: "unsupported",
  };

  const publicKey = normalizeHex(report.signing_public_key);
  const signingKey = normalizeHex(report.signing_key);
  const hasDuplicateSigningKey = typeof report.signing_key === "string";
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
        details: [
          buildDetail("Reported signing address", reportedAddress),
          buildDetail("Derived address from public key", derivedSigningAddress),
        ],
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
        details: [
          buildDetail("Reported signing address", reportedAddress),
          buildDetail("Derived address from public key", derivedSigningAddress),
        ],
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
        !hasDuplicateSigningKey
          ? "The optional duplicate signing_key field is absent, so binding checks rely on signing_public_key only."
          : publicKey && signingKey && publicKey.toLowerCase() === signingKey.toLowerCase()
          ? "The duplicated signing key fields agree."
          : "The signing key fields disagree or one is missing.",
      details: [
        buildDetail("signing_public_key", publicKey),
        buildDetail("signing_key", signingKey),
      ],
      domain: "binding",
      id: "signing-key-consistency",
      jsonPath: "$.signing_key",
      label: "Check signing key consistency",
      severity: "blocking",
      source: "local",
      status:
        !hasDuplicateSigningKey
          ? "info"
          : publicKey && signingKey && publicKey.toLowerCase() === signingKey.toLowerCase()
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
      details: [
        buildDetail("Attestation nonce", nonce),
        buildDetail("Request nonce", requestNonce),
      ],
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
      details: [
        buildDetail("Attestation nonce", nonce),
        buildDetail("NVIDIA payload nonce", nvidiaNonce),
      ],
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
      severity: "advisory",
    });

    checks.push(...appCertResult.checks);
  } else {
    checks.push(
      buildCheck({
        description:
          "The info block does not include an app certificate bundle. App certificates are informational unless explicitly bound to the attested workload.",
        domain: "app-cert",
        id: "app-certificate-bundle",
        jsonPath: "$.info.app_cert",
        label: "Inspect app certificate bundle",
        severity: "advisory",
        source: "local",
        status: "info",
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
      quote,
    });
    checks.push(...tdxCryptoResult.checks);
    if (tdxCryptoResult.baseCryptoPassed) {
      const collateralResult = await evaluateTdxCollateral({
        pckExtensions: tdxCryptoResult.pckExtensions,
        qeReport: tdxCryptoResult.qeReport,
        quote,
        report,
      });
      checks.push(...collateralResult.checks);
      evidenceStatus.intel = collateralResult.status;
    }
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
    evidenceList,
    expectedArch: normalizeNvidiaArchitecture(report.nvidia_payload.arch),
    expectedNonce: nvidiaNonce,
  });
  checks.push(...nvidiaCryptoResult.checks);
  evidenceStatus.nvidia = nvidiaCryptoResult.status;

  checks.push(...buildEventLogChecks(report));
  checks.push(...buildKeyProviderChecks(report));

  const serverClaims = evaluateEmbeddedClaims(report, derivedSigningAddress);
  checks.push(...serverClaims.checks);
  verifiedAt = serverClaims.verifiedAt;

  return {
    checks,
    cryptographicStatus: deriveOverallCryptographicStatus(evidenceStatus),
    derivedSigningAddress,
    evidenceStatus,
    mode: "offline",
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
        composeHash && mrConfigIdEmbedsComposeHash(quote.mrConfigId, composeHash)
          ? "The quote MRCONFIGID embeds the reported compose hash."
          : "The quote MRCONFIGID does not embed the reported compose hash.",
      domain: "tdx",
      id: "tdx-compose-hash",
      jsonPath: "$.info.compose_hash",
      label: "Check quote MRCONFIGID against compose hash",
      severity: "blocking",
      source: "local",
      status:
        composeHash && mrConfigIdEmbedsComposeHash(quote.mrConfigId, composeHash)
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
  const checks: CheckResult[] = [
    buildHexEventBindingCheck({
      actualValues: eventMap["app-id"] ?? [],
      expectedValue: info?.app_id,
      id: "event-log-app-id",
      label: "Check event log app ID binding",
      matchingDescription: "The event log app-id matches the info block.",
      mismatchDescription: "The event log app-id does not match the info block.",
    }),
    buildHexEventBindingCheck({
      actualValues: eventMap["compose-hash"] ?? [],
      expectedValue: info?.compose_hash,
      id: "event-log-compose-hash",
      label: "Check event log compose hash binding",
      matchingDescription: "The event log compose hash matches the info block.",
      mismatchDescription: "The event log compose hash does not match the info block.",
    }),
    buildHexEventBindingCheck({
      actualValues: eventMap["instance-id"] ?? [],
      expectedValue: info?.instance_id,
      id: "event-log-instance-id",
      label: "Check event log instance ID binding",
      matchingDescription: "The event log instance-id matches the info block.",
      mismatchDescription: "The event log instance-id does not match the info block.",
    }),
    buildHexEventBindingCheck({
      actualValues: eventMap["os-image-hash"] ?? [],
      expectedValue: tcbInfo?.os_image_hash,
      id: "event-log-os-image-hash",
      label: "Check event log OS image hash binding",
      matchingDescription: "The event log OS image hash matches the TCB info.",
      mismatchDescription: "The event log OS image hash does not match the TCB info.",
    }),
  ];

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
  const checks: CheckResult[] = [];

  const infoKeyProvider = parseJsonObject(info?.key_provider_info);
  const distinctKeyProviderPayloads = distinctNormalizedValues(eventMap["key-provider"] ?? []);
  const eventKeyProvider =
    distinctKeyProviderPayloads.length === 1
      ? parseJsonObject(hexToUtf8(distinctKeyProviderPayloads[0]!))
      : undefined;

  checks.push(
    buildCheck({
      description:
        distinctKeyProviderPayloads.length > 1
          ? "The event log contains conflicting key-provider payloads."
          : infoKeyProvider &&
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
        distinctKeyProviderPayloads.length > 1
          ? "fail"
          : infoKeyProvider &&
            eventKeyProvider &&
            JSON.stringify(infoKeyProvider) === JSON.stringify(eventKeyProvider)
          ? "pass"
          : "fail",
    }),
  );

  return checks;
}

async function evaluateTdxCollateral({
  pckExtensions,
  qeReport,
  quote,
  report,
}: {
  pckExtensions?: ReturnType<typeof parseIntelPckExtensions>;
  qeReport?: ReturnType<typeof parseQeReport>;
  quote: DecodedQuote;
  report: NormalizedAttestationReport;
}): Promise<DomainVerificationResult> {
  const checks: CheckResult[] = [];
  const collateral = extractIntelCollateral(report);
  const hasCompleteCollateral =
    collateral.qeIdentity.value !== undefined &&
    collateral.signedTcbInfo.value !== undefined &&
    collateral.tcbSignChain.value !== undefined;
  const anyCollateralPresent =
    collateral.qeIdentity.rawValue !== undefined ||
    collateral.signedTcbInfo.rawValue !== undefined ||
    collateral.tcbSignChain.rawValue !== undefined;

  checks.push(
    buildCheck({
      description: hasCompleteCollateral
        ? "The raw report includes Intel QE identity, signed TCB info, and TCB signing chain collateral."
        : "The raw report does not include a complete Intel collateral set, so Intel verification remains partial after quote cryptography.",
      details: [
        buildDetail("QE identity path", collateral.qeIdentity.jsonPath),
        buildDetail("Signed TCB info path", collateral.signedTcbInfo.jsonPath),
        buildDetail("TCB signing chain path", collateral.tcbSignChain.jsonPath),
      ],
      domain: "tdx",
      id: "intel-collateral-availability",
      jsonPath: "$",
      label: "Inspect Intel collateral availability",
      severity: "advisory",
      source: "local",
      status: hasCompleteCollateral ? "pass" : anyCollateralPresent ? "fail" : "info",
    }),
  );

  if (!hasCompleteCollateral || !pckExtensions || !qeReport) {
    return {
      checks,
      status: "partial",
    };
  }

  const qeIdentity = collateral.qeIdentity.value;
  const signedTcbInfo = collateral.signedTcbInfo.value;
  const tcbSignChain = collateral.tcbSignChain.value;
  if (!qeIdentity || !signedTcbInfo || !tcbSignChain) {
    return {
      checks,
      status: "partial",
    };
  }

  const signingChainResult = await validateCertificateChain({
    bundle: tcbSignChain,
    bundleLabel: "Intel TCB signing chain",
    domain: "intel",
    jsonPath: collateral.tcbSignChain.jsonPath,
    severity: "advisory",
  });
  checks.push(...signingChainResult.checks);

  const qeIdentitySignatureValid = await verifyIntelCollateralSignature({
    body: qeIdentity.enclaveIdentity,
    chain: signingChainResult.chain ?? [],
    signatureHex: qeIdentity.signature,
  });
  checks.push(
    buildCheck({
      description: qeIdentitySignatureValid
        ? "The Intel QE identity signature validates against the Intel TCB signing chain."
        : "The Intel QE identity signature does not validate against the Intel TCB signing chain.",
      domain: "tdx",
      id: "intel-qe-identity-signature",
      jsonPath: collateral.qeIdentity.jsonPath,
      label: "Verify Intel QE identity signature",
      severity: "advisory",
      source: "local",
      status: qeIdentitySignatureValid ? "pass" : "fail",
    }),
  );

  const qeIdentityEvaluation = evaluateQeIdentity({
    qeIdentity: qeIdentity.enclaveIdentity,
    qeReport,
  });
  checks.push(
    buildCheck({
      description: qeIdentityEvaluation.acceptable
        ? "The QE report matches the signed Intel QE identity."
        : "The QE report does not fully match the signed Intel QE identity.",
      details: [
        buildDetail("QE identity status", qeIdentityEvaluation.status),
        buildDetail("MRSIGNER match", qeIdentityEvaluation.mrsignerMatch),
      ],
      domain: "tdx",
      id: "intel-qe-identity-match",
      jsonPath: collateral.qeIdentity.jsonPath,
      label: "Check Intel QE identity match",
      severity: "advisory",
      source: "local",
      status: qeIdentityEvaluation.acceptable ? "pass" : "fail",
    }),
  );

  const qeIdentityCurrent = isCollateralCurrent(qeIdentity.enclaveIdentity);
  checks.push(
    buildCheck({
      description: qeIdentityCurrent
        ? "The signed Intel QE identity is within its validity window."
        : "The signed Intel QE identity is outside its validity window.",
      domain: "tdx",
      id: "intel-qe-identity-validity",
      jsonPath: collateral.qeIdentity.jsonPath,
      label: "Check Intel QE identity freshness",
      severity: "advisory",
      source: "local",
      status: qeIdentityCurrent ? "pass" : "fail",
    }),
  );

  const tcbInfoSignatureValid = await verifyIntelCollateralSignature({
    body: signedTcbInfo.tcbInfo,
    chain: signingChainResult.chain ?? [],
    signatureHex: signedTcbInfo.signature,
  });
  checks.push(
    buildCheck({
      description: tcbInfoSignatureValid
        ? "The Intel signed TCB info validates against the Intel TCB signing chain."
        : "The Intel signed TCB info does not validate against the Intel TCB signing chain.",
      domain: "tdx",
      id: "intel-tcb-info-signature",
      jsonPath: collateral.signedTcbInfo.jsonPath,
      label: "Verify Intel TCB info signature",
      severity: "advisory",
      source: "local",
      status: tcbInfoSignatureValid ? "pass" : "fail",
    }),
  );

  const tcbEvaluation = evaluateTcbInfo({
    pckExtensions,
    quoteMrSignerSeam: quote.mrSignerSeam,
    quoteSeamAttributes: quote.seamAttributes,
    quoteTeeTcbSvn: quote.teeTcbSvn,
    tcbInfo: signedTcbInfo.tcbInfo,
  });
  checks.push(
    buildCheck({
      description: tcbEvaluation.acceptable
        ? "The quote and PCK extensions satisfy the signed Intel TCB info."
        : "The quote and PCK extensions do not satisfy the signed Intel TCB info.",
      details: [
        buildDetail("TCB status", tcbEvaluation.status),
        buildDetail("FMSPC match", tcbEvaluation.fmspcMatch),
        buildDetail("PCE ID match", tcbEvaluation.pceIdMatch),
      ],
      domain: "tdx",
      id: "intel-tcb-info-match",
      jsonPath: collateral.signedTcbInfo.jsonPath,
      label: "Check Intel TCB level match",
      severity: "advisory",
      source: "local",
      status: tcbEvaluation.acceptable ? "pass" : "fail",
    }),
  );

  const tcbInfoCurrent = isCollateralCurrent(signedTcbInfo.tcbInfo);
  checks.push(
    buildCheck({
      description: tcbInfoCurrent
        ? "The Intel signed TCB info is within its validity window."
        : "The Intel signed TCB info is outside its validity window.",
      domain: "tdx",
      id: "intel-tcb-info-validity",
      jsonPath: collateral.signedTcbInfo.jsonPath,
      label: "Check Intel TCB info freshness",
      severity: "advisory",
      source: "local",
      status: tcbInfoCurrent ? "pass" : "fail",
    }),
  );

  const fullyVerified =
    !hasFailures(signingChainResult.checks) &&
    qeIdentitySignatureValid &&
    qeIdentityEvaluation.acceptable &&
    qeIdentityCurrent &&
    tcbInfoSignatureValid &&
    tcbEvaluation.acceptable &&
    tcbInfoCurrent;

  return {
    checks,
    status: fullyVerified ? "verified" : "partial",
  };
}

async function verifyTdxQuoteCryptography({
  quote,
}: {
  quote: DecodedQuote;
}): Promise<TdxCryptographyResult> {
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
      baseCryptoPassed: false,
      checks,
    };
  }

  checks.push(
    buildCheck({
      description:
        quote.outerCertificationDataType === TDX_QE_REPORT_CERTIFICATION_DATA_TYPE
          ? "The quote uses the expected QE report certification wrapper for TDX v4."
          : `The quote uses unsupported outer certification data type ${String(
              quote.outerCertificationDataType,
            )}.`,
      domain: "tdx",
      id: "tdx-qe-report-certification-data",
      jsonPath: "$.intel_quote",
      label: "Inspect QE report certification wrapper",
      severity: "blocking",
      source: "local",
      status:
        quote.outerCertificationDataType === TDX_QE_REPORT_CERTIFICATION_DATA_TYPE
          ? "pass"
          : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description:
        quote.certificationDataType === TDX_PCK_CERT_CHAIN_CERTIFICATION_DATA_TYPE
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
      status:
        quote.certificationDataType === TDX_PCK_CERT_CHAIN_CERTIFICATION_DATA_TYPE
          ? "pass"
          : "fail",
    }),
  );

  const chainResult = await validateCertificateChain({
    bundle: quote.certificationData,
    bundleLabel: "Intel PCK certificate chain",
    domain: "intel",
    jsonPath: "$.intel_quote",
  });

  checks.push(...chainResult.checks);

  const localQuoteSignatureValid = await verifyEcdsaSignature({
    hash: "SHA-256",
    namedCurve: "P-256",
    payload: quote.quoteBytes.slice(0, TDX_AUTH_DATA_LENGTH_OFFSET),
    publicKey: quote.attestationPublicKey,
    signature: quote.quoteSignature,
    signatureFormat: "ieee-p1363",
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
    const pckPublicKey = await crypto.subtle.importKey(
      "spki",
      toArrayBuffer(new Uint8Array(chainResult.chain[0].publicKey.rawData)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    qeReportSignatureValid = await verifyEcdsaSignature({
      hash: "SHA-256",
      namedCurve: "P-256",
      payload: quote.qeReport,
      publicKey: pckPublicKey,
      signature: quote.qeReportSignature,
      signatureFormat: "ieee-p1363",
    });
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
      details: [
        buildDetail("Expected QE report data hash", expectedQeReportData),
        buildDetail("Actual QE report data", actualQeReportData),
      ],
      domain: "tdx",
      id: "tdx-qe-report-data",
      jsonPath: "$.intel_quote",
      label: "Check QE report data binding",
      severity: "blocking",
      source: "local",
      status: qeReportDataMatches ? "pass" : "fail",
    }),
  );

  const pckExtensions = chainResult.chain?.[0]
    ? parseIntelPckExtensions(chainResult.chain[0])
    : undefined;
  const qeReport = parseQeReport(quote.qeReport);

  checks.push(
    buildCheck({
      description: qeReport
        ? "The QE report parsed into structured fields for collateral evaluation."
        : "The QE report could not be parsed into structured fields for collateral evaluation.",
      domain: "tdx",
      id: "intel-qe-report-parse",
      jsonPath: "$.intel_quote",
      label: "Parse Intel QE report",
      severity: "blocking",
      source: "local",
      status: qeReport ? "pass" : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description: pckExtensions
        ? "The Intel PCK leaf certificate exposes the SGX/TDX extension values needed for TCB evaluation."
        : "The Intel PCK leaf certificate is missing the SGX/TDX extension values needed for TCB evaluation.",
      domain: "tdx",
      id: "intel-pck-extensions",
      jsonPath: "$.intel_quote",
      label: "Parse Intel PCK extensions",
      severity: "blocking",
      source: "local",
      status: pckExtensions ? "pass" : "fail",
    }),
  );

  const baseCryptoPassed =
    localQuoteSignatureValid &&
    qeReportSignatureValid &&
    qeReportDataMatches &&
    qeReport !== undefined &&
    pckExtensions !== undefined &&
    !hasBlockingFailures(chainResult.checks);

  return {
    baseCryptoPassed,
    checks,
    pckExtensions,
    qeReport,
  };
}

async function verifyNvidiaEvidence({
  evidenceList,
  expectedArch,
  expectedNonce,
}: {
  evidenceList: NormalizedAttestationReport["nvidia_payload"]["evidence_list"];
  expectedArch?: string;
  expectedNonce?: string;
}): Promise<DomainVerificationResult> {
  const checks: CheckResult[] = [];

  if (evidenceList.length === 0) {
    return {
      checks,
      status: "unsupported",
    };
  }

  let everyEntryVerified = true;
  let anyEntryParsed = false;

  for (const [index, entry] of evidenceList.entries()) {
    const certificatePem = decodeBase64Utf8(entry.certificate);
    const chainResult = await validateCertificateChain({
      bundle: certificatePem,
      bundleLabel: `NVIDIA certificate chain ${index + 1}`,
      domain: "nvidia",
      jsonPath: `$.nvidia_payload.evidence_list[${index}].certificate`,
    });

    checks.push(...chainResult.checks);

    const evidenceBytes = normalizeBase64(entry.evidence);
    checks.push(
      buildCheck({
        description:
          evidenceBytes !== undefined
            ? "The NVIDIA evidence blob is present and decodes from base64."
            : "The NVIDIA evidence blob is missing or not valid base64.",
        domain: "nvidia",
        id: `nvidia-evidence-base64-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].evidence`,
        label: "Decode NVIDIA evidence blob",
        severity: "blocking",
        source: "local",
        status: evidenceBytes !== undefined ? "pass" : "fail",
      }),
    );

    const leafCertificate = chainResult.chain?.[0];
    const parsedEvidence =
      evidenceBytes && leafCertificate
        ? parseNvidiaEvidence({
            arch: entry.arch,
            evidence: evidenceBytes,
            leafCertificate,
          })
        : undefined;

    checks.push(
      buildCheck({
        description: parsedEvidence
          ? "The NVIDIA evidence blob parsed successfully as request, response, opaque data, and signature sections."
          : "The NVIDIA evidence blob did not parse as a supported NVIDIA SPDM evidence structure.",
        domain: "nvidia",
        id: `nvidia-evidence-parse-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].evidence`,
        label: "Parse NVIDIA raw evidence",
        severity: "blocking",
        source: "local",
        status: parsedEvidence ? "pass" : "fail",
      }),
    );

    if (!parsedEvidence || !leafCertificate) {
      everyEntryVerified = false;
      continue;
    }

    anyEntryParsed = true;

    const signatureValid = await verifyNvidiaEvidenceSignature({
      leafCertificate,
      signature: parsedEvidence.signature,
      signedBytes: parsedEvidence.signedBytes,
    });

    checks.push(
      buildCheck({
        description: signatureValid
          ? "The NVIDIA raw evidence signature validates against the leaf certificate public key."
          : "The NVIDIA raw evidence signature does not validate against the leaf certificate public key.",
        domain: "nvidia",
        id: `nvidia-evidence-signature-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].evidence`,
        label: "Verify NVIDIA evidence signature",
        severity: "blocking",
        source: "local",
        status: signatureValid ? "pass" : "fail",
      }),
    );

    const nonceMatches = Boolean(expectedNonce && parsedEvidence.requestNonce === expectedNonce);
    checks.push(
      buildCheck({
        description: nonceMatches
          ? "The NVIDIA evidence request nonce matches the attestation report nonce."
          : "The NVIDIA evidence request nonce does not match the attestation report nonce.",
        details: [
          buildDetail("Expected attestation nonce", expectedNonce),
          buildDetail("Evidence request nonce", parsedEvidence.requestNonce),
        ],
        domain: "nvidia",
        id: `nvidia-evidence-request-nonce-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].evidence`,
        label: "Check NVIDIA evidence nonce binding",
        severity: "blocking",
        source: "local",
        status: nonceMatches ? "pass" : "fail",
      }),
    );

    const actualArch = normalizeNvidiaArchitecture(entry.arch ?? parsedEvidence.arch);
    const archMatches =
      expectedArch !== undefined ? actualArch === expectedArch : actualArch !== undefined;

    checks.push(
      buildCheck({
        description: archMatches
          ? "The reported NVIDIA architecture metadata is internally consistent."
          : "The reported NVIDIA architecture metadata is inconsistent. This field is advisory because it is not independently derived from the raw evidence.",
        details: [
          buildDetail("Reported payload architecture", expectedArch),
          buildDetail("Entry architecture metadata", actualArch),
        ],
        domain: "nvidia",
        id: `nvidia-evidence-arch-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].arch`,
        label: "Compare NVIDIA architecture metadata",
        severity: "advisory",
        source: "local",
        status:
          expectedArch === undefined && actualArch === undefined
            ? "info"
            : archMatches
              ? "pass"
              : "fail",
      }),
    );

    const fwidMatches =
      parsedEvidence.evidenceFwid !== undefined &&
      parsedEvidence.leafCertificateFwid !== undefined &&
      parsedEvidence.evidenceFwid === parsedEvidence.leafCertificateFwid;

    checks.push(
      buildCheck({
        description: fwidMatches
          ? "The NVIDIA FWID extracted from opaque evidence matches the device certificate FWID."
          : "The NVIDIA FWID extracted from opaque evidence does not match the device certificate FWID.",
        details: [
          buildDetail("FWID from evidence", parsedEvidence.evidenceFwid),
          buildDetail("FWID from certificate", parsedEvidence.leafCertificateFwid),
        ],
        domain: "nvidia",
        id: `nvidia-evidence-fwid-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].evidence`,
        label: "Check NVIDIA FWID binding",
        severity: "blocking",
        source: "local",
        status: fwidMatches ? "pass" : "fail",
      }),
    );

    const opaqueVersionSupported =
      parsedEvidence.opaqueDataVersion === undefined ||
      parsedEvidence.opaqueDataVersion <= 1;
    checks.push(
      buildCheck({
        description:
          parsedEvidence.opaqueDataVersion === undefined
            ? "The NVIDIA evidence did not expose an opaque-data version field."
            : opaqueVersionSupported
              ? `The NVIDIA evidence opaque-data version ${parsedEvidence.opaqueDataVersion} is supported.`
              : `The NVIDIA evidence opaque-data version ${parsedEvidence.opaqueDataVersion} is not supported.`,
        details: [
          buildDetail("Opaque-data version", parsedEvidence.opaqueDataVersion),
          buildDetail("Maximum supported version", 1),
        ],
        domain: "nvidia",
        id: `nvidia-evidence-opaque-version-${index}`,
        jsonPath: `$.nvidia_payload.evidence_list[${index}].evidence`,
        label: "Inspect NVIDIA opaque-data version",
        severity: "blocking",
        source: "local",
        status:
          parsedEvidence.opaqueDataVersion === undefined || opaqueVersionSupported
            ? "pass"
            : "fail",
      }),
    );

    if (
      hasBlockingFailures(chainResult.checks) ||
      !signatureValid ||
      !nonceMatches ||
      !fwidMatches ||
      !opaqueVersionSupported
    ) {
      everyEntryVerified = false;
    }
  }

  return {
    checks,
    status: everyEntryVerified && anyEntryParsed ? "verified" : anyEntryParsed ? "partial" : "unsupported",
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
          "No embedded server verification block was present. Embedded Venice or NRAS claims are optional provenance only and do not control the verdict.",
        domain: "provenance",
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
          ? "The report includes an embedded verified flag reported by an upstream Venice or NRAS verifier."
          : "The report does not include an embedded verified flag.",
      details: [
        buildDetail("Embedded verified flag", report.verified),
        buildDetail("Embedded verifiedAt", verifiedAt),
      ],
      domain: "provenance",
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
      details: [
        buildDetail(
          "Embedded server_verification.tdx.valid",
          isRecord(tdx) ? tdx.valid : undefined,
        ),
        buildDetail("Embedded verifiedAt", verifiedAt),
      ],
      domain: "provenance",
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
      details: [
        buildDetail(
          "Embedded server_verification.nvidia.valid",
          isRecord(nvidia) ? nvidia.valid : undefined,
        ),
        buildDetail("Embedded verifiedAt", verifiedAt),
      ],
      domain: "provenance",
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
      details: [
        buildDetail("Embedded report-data address", embeddedAddress),
        buildDetail("Locally derived signing address", derivedSigningAddress),
        buildDetail("Embedded verifiedAt", verifiedAt),
      ],
      domain: "provenance",
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

export function decodeTdxQuote(value: unknown): DecodedQuote | undefined {
  const quoteHex = normalizeHex(value);
  if (!quoteHex) {
    return undefined;
  }

  try {
    const quoteBytes = hexToBytes(`0x${quoteHex}`);
    if (quoteBytes.length < TDX_AUTH_DATA_OFFSET) {
      return undefined;
    }

    const view = new DataView(
      quoteBytes.buffer,
      quoteBytes.byteOffset,
      quoteBytes.byteLength,
    );
    const authDataLength = view.getUint32(TDX_AUTH_DATA_LENGTH_OFFSET, true);
    if (quoteBytes.length < TDX_AUTH_DATA_OFFSET + authDataLength) {
      return undefined;
    }

    const authData = quoteBytes.slice(
      TDX_AUTH_DATA_OFFSET,
      TDX_AUTH_DATA_OFFSET + authDataLength,
    );
    if (authData.length < TDX_QUOTE_SIGNATURE_LENGTH + TDX_ATTESTATION_KEY_LENGTH + 6) {
      return undefined;
    }

    let offset = 0;
    const quoteSignature = authData.slice(offset, offset + TDX_QUOTE_SIGNATURE_LENGTH);
    offset += TDX_QUOTE_SIGNATURE_LENGTH;
    const attestationPublicKey = authData.slice(
      offset,
      offset + TDX_ATTESTATION_KEY_LENGTH,
    );
    offset += TDX_ATTESTATION_KEY_LENGTH;

    const outerCertificationDataType = new DataView(
      authData.buffer,
      authData.byteOffset,
      authData.byteLength,
    ).getUint16(offset, true);
    const outerCertificationDataSize = new DataView(
      authData.buffer,
      authData.byteOffset,
      authData.byteLength,
    ).getUint32(offset + 2, true);
    offset += 6;

    if (offset + outerCertificationDataSize > authData.length) {
      return undefined;
    }

    const outerCertificationData = authData.slice(
      offset,
      offset + outerCertificationDataSize,
    );
    if (outerCertificationData.length < TDX_QE_REPORT_LENGTH + TDX_QE_REPORT_SIGNATURE_LENGTH + 8) {
      return undefined;
    }

    let certOffset = 0;
    const qeReport = outerCertificationData.slice(
      certOffset,
      certOffset + TDX_QE_REPORT_LENGTH,
    );
    certOffset += TDX_QE_REPORT_LENGTH;
    const qeReportSignature = outerCertificationData.slice(
      certOffset,
      certOffset + TDX_QE_REPORT_SIGNATURE_LENGTH,
    );
    certOffset += TDX_QE_REPORT_SIGNATURE_LENGTH;

    const qeAuthDataSize = new DataView(
      outerCertificationData.buffer,
      outerCertificationData.byteOffset,
      outerCertificationData.byteLength,
    ).getUint16(certOffset, true);
    certOffset += 2;
    const qeAuthData = outerCertificationData.slice(
      certOffset,
      certOffset + qeAuthDataSize,
    );
    certOffset += qeAuthDataSize;

    if (certOffset + 6 > outerCertificationData.length) {
      return undefined;
    }

    const certificationDataType = new DataView(
      outerCertificationData.buffer,
      outerCertificationData.byteOffset,
      outerCertificationData.byteLength,
    ).getUint16(certOffset, true);
    const certificationDataSize = new DataView(
      outerCertificationData.buffer,
      outerCertificationData.byteOffset,
      outerCertificationData.byteLength,
    ).getUint32(certOffset + 2, true);
    certOffset += 6;

    if (certOffset + certificationDataSize > outerCertificationData.length) {
      return undefined;
    }

    const certificationData = outerCertificationData.slice(
      certOffset,
      certOffset + certificationDataSize,
    );

    return {
      attestationPublicKey,
      certificationData: decodeCertificationDataBundle(certificationData),
      certificationDataType,
      mrConfigId: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrConfigId.offset,
        TDX_FIELD_LAYOUT.mrConfigId.length,
      ),
      mrOwner: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrOwner.offset,
        TDX_FIELD_LAYOUT.mrOwner.length,
      ),
      mrOwnerConfig: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrOwnerConfig.offset,
        TDX_FIELD_LAYOUT.mrOwnerConfig.length,
      ),
      mrSeam: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrSeam.offset,
        TDX_FIELD_LAYOUT.mrSeam.length,
      ),
      mrSignerSeam: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrSignerSeam.offset,
        TDX_FIELD_LAYOUT.mrSignerSeam.length,
      ),
      mrtd: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.mrtd.offset,
        TDX_FIELD_LAYOUT.mrtd.length,
      ),
      outerCertificationDataType,
      qeAuthData,
      qeReport,
      qeReportSignature,
      quoteBytes,
      quoteReportData: toHex(
        qeReport.slice(
          TDX_QE_REPORT_REPORT_DATA_OFFSET,
          TDX_QE_REPORT_REPORT_DATA_OFFSET + TDX_QE_REPORT_REPORT_DATA_LENGTH,
        ),
      ),
      quoteSignature,
      reportData: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.reportData.offset,
        TDX_FIELD_LAYOUT.reportData.length,
      ),
      rtmr0: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.rtmr0.offset,
        TDX_FIELD_LAYOUT.rtmr0.length,
      ),
      rtmr1: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.rtmr1.offset,
        TDX_FIELD_LAYOUT.rtmr1.length,
      ),
      rtmr2: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.rtmr2.offset,
        TDX_FIELD_LAYOUT.rtmr2.length,
      ),
      rtmr3: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.rtmr3.offset,
        TDX_FIELD_LAYOUT.rtmr3.length,
      ),
      seamAttributes: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.seamAttributes.offset,
        TDX_FIELD_LAYOUT.seamAttributes.length,
      ),
      tdAttributes: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.tdAttributes.offset,
        TDX_FIELD_LAYOUT.tdAttributes.length,
      ),
      teeTcbSvn: Array.from(
        extractQuoteFieldBytes(
          quoteBytes,
          TDX_FIELD_LAYOUT.teeTcbSvn.offset,
          TDX_FIELD_LAYOUT.teeTcbSvn.length,
        ),
      ),
      version: view.getUint16(0, true),
      xfam: extractQuoteField(
        quoteBytes,
        TDX_FIELD_LAYOUT.xfam.offset,
        TDX_FIELD_LAYOUT.xfam.length,
      ),
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
  return toHex(
    bytes.slice(TDX_HEADER_LENGTH + offset, TDX_HEADER_LENGTH + offset + length),
  );
}

function extractQuoteFieldBytes(
  bytes: Uint8Array,
  offset: number,
  length: number,
): Uint8Array {
  return bytes.slice(TDX_HEADER_LENGTH + offset, TDX_HEADER_LENGTH + offset + length);
}

function mrConfigIdEmbedsComposeHash(
  mrConfigId: string,
  composeHash: string,
): boolean {
  if (mrConfigId.length < composeHash.length) {
    return false;
  }

  if (mrConfigId.startsWith(composeHash)) {
    return true;
  }

  // Some Venice producers write MRCONFIGID as 0x01 || compose_hash || zero padding.
  return (
    mrConfigId.length >= composeHash.length + 2 &&
    mrConfigId.startsWith("01") &&
    mrConfigId.slice(2, 2 + composeHash.length) === composeHash &&
    /^0*$/.test(mrConfigId.slice(2 + composeHash.length))
  );
}

function collectNamedEventPayloads(
  value: NormalizedAttestationReport["event_log"],
): Record<string, string[]> {
  const namedPayloads: Record<string, string[]> = {};

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

    const key = entry.event.trim();
    const existing = namedPayloads[key] ?? [];
    existing.push(entry.event_payload);
    namedPayloads[key] = existing;
  }

  return namedPayloads;
}

function buildHexEventBindingCheck({
  actualValues,
  expectedValue,
  id,
  label,
  matchingDescription,
  mismatchDescription,
}: {
  actualValues: string[];
  expectedValue: unknown;
  id: string;
  label: string;
  matchingDescription: string;
  mismatchDescription: string;
}): CheckResult {
  const distinctActualValues = distinctNormalizedValues(actualValues);
  const expected = normalizeHex(expectedValue);
  const isAmbiguous = distinctActualValues.length > 1;
  const actual = distinctActualValues.length === 1 ? distinctActualValues[0] : undefined;

  return buildCheck({
    description: isAmbiguous
      ? "The event log contains multiple conflicting payloads for this security-critical event."
      : actual && expected && actual === expected
        ? matchingDescription
        : mismatchDescription,
    domain: "event-log",
    id,
    jsonPath: "$.event_log",
    label,
    severity: "blocking",
    source: "local",
    status: isAmbiguous ? "fail" : actual && expected && actual === expected ? "pass" : "fail",
  });
}

function distinctNormalizedValues(values: string[]): string[] {
  return Array.from(
    new Set(values.map((value) => normalizeHex(value)).filter((value): value is string => Boolean(value))),
  );
}

function extractIntelCollateral(report: NormalizedAttestationReport): {
  qeIdentity: CollateralField<IntelSignedQeIdentity>;
  signedTcbInfo: CollateralField<IntelSignedTcbInfo>;
  tcbSignChain: CollateralField<string>;
} {
  return {
    qeIdentity: pickCollateralField(report, [
      "$.intel_qe_identity",
      "$.qe_identity",
      "$.intel.qe_identity",
      "$.intel.qeIdentity",
      "$.intel_collateral.qe_identity",
      "$.intel_collateral.qeIdentity",
    ], asIntelSignedQeIdentity),
    signedTcbInfo: pickCollateralField(report, [
      "$.intel_signed_tcb_info",
      "$.intel_tcb_info",
      "$.intel.signed_tcb_info",
      "$.intel.tcb_info",
      "$.intel.signedTcbInfo",
      "$.intel.tcbInfo",
      "$.intel_collateral.signed_tcb_info",
      "$.intel_collateral.tcb_info",
      "$.intel_collateral.signedTcbInfo",
      "$.intel_collateral.tcbInfo",
    ], asIntelSignedTcbInfo),
    tcbSignChain: pickCollateralField(report, [
      "$.intel_tcb_sign_chain",
      "$.intel_tcb_signing_chain",
      "$.tcb_sign_chain",
      "$.intel.tcb_sign_chain",
      "$.intel.tcb_signing_chain",
      "$.intel.tcbSignChain",
      "$.intel.tcbSigningChain",
      "$.intel_collateral.tcb_sign_chain",
      "$.intel_collateral.tcb_signing_chain",
      "$.intel_collateral.tcbSignChain",
      "$.intel_collateral.tcbSigningChain",
    ], (value) => typeof value === "string" && value.length > 0 ? value : undefined),
  };
}

type CollateralField<T> = {
  jsonPath: string;
  rawValue?: unknown;
  value?: T;
};

function pickCollateralField<T>(
  report: NormalizedAttestationReport,
  candidatePaths: string[],
  parser: (value: unknown) => T | undefined,
): CollateralField<T> {
  for (const path of candidatePaths) {
    const rawValue = readPath(report, path);
    if (rawValue === undefined) {
      continue;
    }

    return {
      jsonPath: path,
      rawValue,
      value: parser(rawValue),
    };
  }

  return {
    jsonPath: candidatePaths[0] ?? "$",
  };
}

function readPath(value: unknown, path: string): unknown {
  if (!path.startsWith("$")) {
    return undefined;
  }

  const segments = path
    .replace(/^\$\./, "")
    .split(".")
    .filter((segment) => segment.length > 0);

  let current: unknown = value;
  for (const segment of segments) {
    if (!isRecord(current) || !(segment in current)) {
      return undefined;
    }

    current = current[segment];
  }

  return current;
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

function deriveOverallCryptographicStatus(evidenceStatus: {
  intel: EvidenceVerificationStatus;
  nvidia: EvidenceVerificationStatus;
}): CryptographicVerificationStatus {
  if (evidenceStatus.intel === "verified" && evidenceStatus.nvidia === "verified") {
    return "verified";
  }

  if (evidenceStatus.intel !== "unsupported" || evidenceStatus.nvidia !== "unsupported") {
    return "partial";
  }

  return "unsupported";
}

function decodeCertificationDataBundle(bytes: Uint8Array): string {
  const text = new TextDecoder().decode(bytes);
  if (text.includes("BEGIN CERTIFICATE")) {
    return text;
  }

  const certificates: string[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    const parsed = parseDerAt(bytes, offset);
    certificates.push(toPemCertificate(bytes.slice(offset, parsed.nextOffset)));
    offset = parsed.nextOffset;
  }

  return certificates.reverse().join("\n");
}

function toPemCertificate(derBytes: Uint8Array): string {
  const base64 = btoa(
    String.fromCharCode(...derBytes),
  ).match(/.{1,64}/g)?.join("\n");

  return `-----BEGIN CERTIFICATE-----\n${base64 ?? ""}\n-----END CERTIFICATE-----`;
}

function hasBlockingFailures(checks: CheckResult[]): boolean {
  return checks.some(
    (check) => check.severity === "blocking" && check.status === "fail",
  );
}

function hasFailures(checks: CheckResult[]): boolean {
  return checks.some((check) => check.status === "fail");
}

function buildCheck({
  description,
  details,
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
    details,
    domain,
    id,
    jsonPath,
    label,
    severity,
    source,
    status,
  };
}

function buildDetail(
  label: string,
  value: unknown,
): CheckDetail {
  if (
    value !== undefined &&
    typeof value !== "boolean" &&
    typeof value !== "number" &&
    typeof value !== "string"
  ) {
    return {
      label,
      value: "Unavailable",
    };
  }

  if (value === undefined) {
    return {
      label,
      value: "Unavailable",
    };
  }

  const text = String(value);
  return {
    copyValue: text,
    label,
    value: text,
  };
}
