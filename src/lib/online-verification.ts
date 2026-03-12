import {
  CRLDistributionPointsExtension,
  X509Certificate,
  X509Crl,
} from "@peculiar/x509";
import type { CheckResult } from "./check-result";
import { validateCertificateChain } from "./certificates";
import { utf8ToBytes, verifyEcdsaSignature } from "./crypto";
import {
  evaluateQeIdentity,
  evaluateTcbInfo,
  isCollateralCurrent,
  type ParsedIntelPckExtensions,
  type ParsedQeReport,
  verifyIntelCollateralSignature,
} from "./intel";
import {
  asIntelSignedQeIdentity,
  asIntelSignedTcbInfo,
  isRecord,
} from "./schema";
import type {
  IntelSignedQeIdentity,
  IntelSignedTcbInfo,
  OnlineVerificationOptions,
} from "./types";

type OnlineVerificationResult = {
  checks: CheckResult[];
  status: "partial" | "verified";
};

const DEFAULT_INTEL_PCS_BASE_URL = "https://api.trustedservices.intel.com";
const DEFAULT_NVIDIA_NRAS_BASE_URL = "https://nras.attestation.nvidia.com/v4";
const DEFAULT_NVIDIA_JWKS_URL =
  "https://nras.attestation.nvidia.com/.well-known/jwks.json";

export async function completeIntelOnlineVerification({
  options,
  pckChain,
  pckExtensions,
  qeReport,
  quoteMrSignerSeam,
  quoteSeamAttributes,
  quoteTeeTcbSvn,
}: {
  options?: OnlineVerificationOptions;
  pckChain: X509Certificate[];
  pckExtensions: ParsedIntelPckExtensions;
  qeReport: ParsedQeReport;
  quoteMrSignerSeam: string;
  quoteSeamAttributes: string;
  quoteTeeTcbSvn: number[];
}): Promise<OnlineVerificationResult> {
  const checks: CheckResult[] = [];
  const fetchImpl = resolveFetch(options?.fetchImpl);

  if (!fetchImpl) {
    checks.push(
      buildCheck({
        description:
          "The app cannot issue live Intel PCS requests in this environment, so Intel online completion could not run.",
        domain: "tdx",
        id: "intel-online-fetch-support",
        jsonPath: "$.intel_quote",
        label: "Enable Intel online verification",
        severity: "advisory",
        source: "online",
        status: "fail",
      }),
    );

    return { checks, status: "partial" };
  }

  const caType = deriveIntelPckCaType(pckChain);
  if (!caType) {
    checks.push(
      buildCheck({
        description:
          "The Intel PCK chain did not expose a processor or platform CA type, so the app could not fetch the matching PCK CRL.",
        details: [
          buildDetail("PCK leaf issuer", pckChain[0]?.issuer),
          buildDetail("PCK intermediate subject", pckChain[1]?.subject),
        ],
        domain: "tdx",
        id: "intel-online-pck-ca-type",
        jsonPath: "$.intel_quote",
        label: "Determine Intel PCK CA type",
        severity: "advisory",
        source: "online",
        status: "fail",
      }),
    );

    return { checks, status: "partial" };
  }

  const baseUrl = normalizeBaseUrl(
    options?.intelBaseUrl ?? DEFAULT_INTEL_PCS_BASE_URL,
  );
  const qeIdentityResponse = await fetchIntelJson({
    fetchImpl,
    headerName: "SGX-Enclave-Identity-Issuer-Chain",
    id: "intel-online-qe-identity-fetch",
    jsonPath: "$.intel_quote",
    label: "Fetch Intel QE identity",
    parser: asIntelSignedQeIdentity,
    url: `${baseUrl}/tdx/certification/v4/qe/identity`,
  });
  checks.push(...qeIdentityResponse.checks);

  const tcbInfoResponse = await fetchIntelJson({
    fetchImpl,
    headerName: "TCB-Info-Issuer-Chain",
    id: "intel-online-tcb-info-fetch",
    jsonPath: "$.intel_quote",
    label: "Fetch Intel TCB info",
    parser: asIntelSignedTcbInfo,
    url: `${baseUrl}/tdx/certification/v4/tcb?fmspc=${encodeURIComponent(
      pckExtensions.fmspc,
    )}&update=standard`,
  });
  checks.push(...tcbInfoResponse.checks);

  const pckCrlResponse = await fetchIntelText({
    fetchImpl,
    headerName: "SGX-PCK-CRL-Issuer-Chain",
    id: "intel-online-pck-crl-fetch",
    jsonPath: "$.intel_quote",
    label: "Fetch Intel PCK CRL",
    url: `${baseUrl}/sgx/certification/v4/pckcrl?ca=${encodeURIComponent(
      caType,
    )}&encoding=pem`,
  });
  checks.push(...pckCrlResponse.checks);

  if (!qeIdentityResponse.ok || !tcbInfoResponse.ok || !pckCrlResponse.ok) {
    return { checks, status: "partial" };
  }

  const qeIdentityChainResult = await validateCertificateChain({
    bundle: qeIdentityResponse.issuerChain,
    bundleLabel: "Intel QE identity issuer chain",
    domain: "intel",
    jsonPath: "$.intel_quote",
    severity: "advisory",
    source: "online",
  });
  checks.push(...qeIdentityChainResult.checks);

  const tcbInfoChainResult = await validateCertificateChain({
    bundle: tcbInfoResponse.issuerChain,
    bundleLabel: "Intel TCB info issuer chain",
    domain: "intel",
    jsonPath: "$.intel_quote",
    severity: "advisory",
    source: "online",
  });
  checks.push(...tcbInfoChainResult.checks);

  const pckCrlChainResult = await validateCertificateChain({
    bundle: pckCrlResponse.issuerChain,
    bundleLabel: "Intel PCK CRL issuer chain",
    domain: "intel",
    jsonPath: "$.intel_quote",
    severity: "advisory",
    source: "online",
  });
  checks.push(...pckCrlChainResult.checks);

  if (
    hasFailedChecks(qeIdentityChainResult.checks) ||
    hasFailedChecks(tcbInfoChainResult.checks) ||
    hasFailedChecks(pckCrlChainResult.checks)
  ) {
    return { checks, status: "partial" };
  }

  const qeIdentitySignatureValid = await verifyIntelCollateralSignature({
    body: qeIdentityResponse.value.enclaveIdentity,
    chain: qeIdentityChainResult.chain ?? [],
    signatureHex: qeIdentityResponse.value.signature,
  });
  checks.push(
    buildCheck({
      description: qeIdentitySignatureValid
        ? "The live Intel QE identity signature validates against the Intel issuer chain."
        : "The live Intel QE identity signature does not validate against the Intel issuer chain.",
      domain: "tdx",
      id: "intel-online-qe-identity-signature",
      jsonPath: "$.intel_quote",
      label: "Verify live Intel QE identity signature",
      severity: "advisory",
      source: "online",
      status: qeIdentitySignatureValid ? "pass" : "fail",
    }),
  );

  const tcbInfoSignatureValid = await verifyIntelCollateralSignature({
    body: tcbInfoResponse.value.tcbInfo,
    chain: tcbInfoChainResult.chain ?? [],
    signatureHex: tcbInfoResponse.value.signature,
  });
  checks.push(
    buildCheck({
      description: tcbInfoSignatureValid
        ? "The live Intel TCB info signature validates against the Intel issuer chain."
        : "The live Intel TCB info signature does not validate against the Intel issuer chain.",
      domain: "tdx",
      id: "intel-online-tcb-info-signature",
      jsonPath: "$.intel_quote",
      label: "Verify live Intel TCB info signature",
      severity: "advisory",
      source: "online",
      status: tcbInfoSignatureValid ? "pass" : "fail",
    }),
  );

  const pckCrlVerification = await verifyIntelPckCrl({
    crlPem: pckCrlResponse.value,
    issuerChain: pckCrlChainResult.chain ?? [],
    pckLeaf: pckChain[0],
  });
  checks.push(...pckCrlVerification.checks);

  const signingChainRevocation = await evaluateIntelSigningChainRevocation({
    certificates: tcbInfoChainResult.chain ?? [],
    fetchImpl,
  });
  checks.push(...signingChainRevocation.checks);

  if (
    !qeIdentitySignatureValid ||
    !tcbInfoSignatureValid ||
    !pckCrlVerification.complete ||
    !signingChainRevocation.complete
  ) {
    return { checks, status: "partial" };
  }

  const qeIdentityEvaluation = evaluateQeIdentity({
    qeIdentity: qeIdentityResponse.value.enclaveIdentity,
    qeReport,
  });
  checks.push(
    buildCheck({
      description: qeIdentityEvaluation.acceptable
        ? "The QE report matches the live Intel QE identity."
        : "The QE report does not match the live Intel QE identity.",
      details: [
        buildDetail("QE identity status", qeIdentityEvaluation.status),
        buildDetail("MRSIGNER match", qeIdentityEvaluation.mrsignerMatch),
      ],
      domain: "tdx",
      id: "intel-online-qe-identity-match",
      jsonPath: "$.intel_quote",
      label: "Check live Intel QE identity match",
      severity: "blocking",
      source: "online",
      status: qeIdentityEvaluation.acceptable ? "pass" : "fail",
    }),
  );

  const qeIdentityCurrent = isCollateralCurrent(qeIdentityResponse.value.enclaveIdentity);
  checks.push(
    buildCheck({
      description: qeIdentityCurrent
        ? "The live Intel QE identity is within its validity window."
        : "The live Intel QE identity is outside its validity window.",
      domain: "tdx",
      id: "intel-online-qe-identity-validity",
      jsonPath: "$.intel_quote",
      label: "Check live Intel QE identity freshness",
      severity: "blocking",
      source: "online",
      status: qeIdentityCurrent ? "pass" : "fail",
    }),
  );

  const tcbEvaluation = evaluateTcbInfo({
    pckExtensions,
    quoteMrSignerSeam,
    quoteSeamAttributes,
    quoteTeeTcbSvn,
    tcbInfo: tcbInfoResponse.value.tcbInfo,
  });
  checks.push(
    buildCheck({
      description: tcbEvaluation.acceptable
        ? "The quote and PCK extensions satisfy the live Intel TCB info."
        : "The quote and PCK extensions do not satisfy the live Intel TCB info.",
      details: [
        buildDetail("TCB status", tcbEvaluation.status),
        buildDetail("FMSPC match", tcbEvaluation.fmspcMatch),
        buildDetail("PCE ID match", tcbEvaluation.pceIdMatch),
      ],
      domain: "tdx",
      id: "intel-online-tcb-info-match",
      jsonPath: "$.intel_quote",
      label: "Check live Intel TCB level match",
      severity: "blocking",
      source: "online",
      status: tcbEvaluation.acceptable ? "pass" : "fail",
    }),
  );

  const tcbInfoCurrent = isCollateralCurrent(tcbInfoResponse.value.tcbInfo);
  checks.push(
    buildCheck({
      description: tcbInfoCurrent
        ? "The live Intel TCB info is within its validity window."
        : "The live Intel TCB info is outside its validity window.",
      domain: "tdx",
      id: "intel-online-tcb-info-validity",
      jsonPath: "$.intel_quote",
      label: "Check live Intel TCB info freshness",
      severity: "blocking",
      source: "online",
      status: tcbInfoCurrent ? "pass" : "fail",
    }),
  );

  const fullyVerified =
    qeIdentityEvaluation.acceptable &&
    qeIdentityCurrent &&
    tcbEvaluation.acceptable &&
    tcbInfoCurrent &&
    !hasBlockingFailures(checks);

  return {
    checks,
    status: fullyVerified ? "verified" : "partial",
  };
}

export async function completeNvidiaOnlineVerification({
  evidenceCount,
  expectedArch,
  expectedNonce,
  options,
  payload,
}: {
  evidenceCount: number;
  expectedArch?: string;
  expectedNonce?: string;
  options?: OnlineVerificationOptions;
  payload: Record<string, unknown>;
}): Promise<OnlineVerificationResult> {
  const checks: CheckResult[] = [];
  const fetchImpl = resolveFetch(options?.fetchImpl);

  if (!fetchImpl) {
    checks.push(
      buildCheck({
        description:
          "The app cannot issue live NVIDIA NRAS requests in this environment, so NVIDIA online completion could not run.",
        domain: "nvidia",
        id: "nvidia-online-fetch-support",
        jsonPath: "$.nvidia_payload",
        label: "Enable NVIDIA online verification",
        severity: "advisory",
        source: "online",
        status: "fail",
      }),
    );

    return { checks, status: "partial" };
  }

  const nrasResponse = await fetchNrasAttestation({
    apiKey: options?.nvidiaApiKey,
    baseUrl: normalizeBaseUrl(
      options?.nvidiaBaseUrl ?? DEFAULT_NVIDIA_NRAS_BASE_URL,
    ),
    fetchImpl,
    payload,
  });
  checks.push(...nrasResponse.checks);

  if (!nrasResponse.ok) {
    return { checks, status: "partial" };
  }

  const tokenBundle = extractNrasTokenBundle(nrasResponse.value);
  checks.push(
    buildCheck({
      description:
        tokenBundle.overallToken && tokenBundle.deviceTokens.length > 0
          ? "NRAS returned an overall EAT and per-device detached EAT tokens."
          : "NRAS did not return the expected overall and per-device detached EAT tokens.",
      details: [
        buildDetail("Device tokens returned", tokenBundle.deviceTokens.length),
        buildDetail("Evidence entries submitted", evidenceCount),
      ],
      domain: "nvidia",
      id: "nvidia-online-detached-eat",
      jsonPath: "$.nvidia_payload",
      label: "Parse NVIDIA detached EAT bundle",
      severity: "advisory",
      source: "online",
      status:
        tokenBundle.overallToken && tokenBundle.deviceTokens.length > 0
          ? "pass"
          : "fail",
    }),
  );

  if (!tokenBundle.overallToken || tokenBundle.deviceTokens.length === 0) {
    return { checks, status: "partial" };
  }

  const jwksResponse = await fetchJson({
    fetchImpl,
    id: "nvidia-online-jwks-fetch",
    jsonPath: "$.nvidia_payload",
    label: "Fetch NVIDIA NRAS JWKS",
    url: options?.nvidiaJwksUrl ?? DEFAULT_NVIDIA_JWKS_URL,
  });
  checks.push(...jwksResponse.checks);

  if (!jwksResponse.ok) {
    checks.push(
      buildCheck({
        description:
          "The NVIDIA JWKS response was missing the signing keys needed to validate NRAS JWTs.",
        domain: "nvidia",
        id: "nvidia-online-jwks-shape",
        jsonPath: "$.nvidia_payload",
        label: "Inspect NVIDIA NRAS JWKS",
        severity: "advisory",
        source: "online",
        status: "fail",
      }),
    );

    return { checks, status: "partial" };
  }

  if (!isJwksResponse(jwksResponse.value)) {
    checks.push(
      buildCheck({
        description:
          "The NVIDIA JWKS response was missing the signing keys needed to validate NRAS JWTs.",
        domain: "nvidia",
        id: "nvidia-online-jwks-shape",
        jsonPath: "$.nvidia_payload",
        label: "Inspect NVIDIA NRAS JWKS",
        severity: "advisory",
        source: "online",
        status: "fail",
      }),
    );

    return { checks, status: "partial" };
  }

  const jwks = jwksResponse.value.keys;

  const overallJwt = decodeJwt(tokenBundle.overallToken);
  const overallSignatureValid = overallJwt
    ? await verifyJwtSignature({
        jwks,
        token: tokenBundle.overallToken,
      })
    : false;
  checks.push(
    buildCheck({
      description: overallSignatureValid
        ? "The NRAS overall EAT validates against the NVIDIA JWKS."
        : "The NRAS overall EAT does not validate against the NVIDIA JWKS.",
      domain: "nvidia",
      id: "nvidia-online-overall-signature",
      jsonPath: "$.nvidia_payload",
      label: "Verify NVIDIA overall EAT signature",
      severity: "advisory",
      source: "online",
      status: overallSignatureValid ? "pass" : "fail",
    }),
  );

  const deviceJwtResults = await Promise.all(
    tokenBundle.deviceTokens.map(async (token, index) => {
      const decoded = decodeJwt(token);
      const signatureValid = decoded
        ? await verifyJwtSignature({
            jwks,
            token,
          })
        : false;

      return {
        decoded,
        index,
        signatureValid,
        token,
      };
    }),
  );

  for (const result of deviceJwtResults) {
    checks.push(
      buildCheck({
        description: result.signatureValid
          ? "The NRAS device EAT validates against the NVIDIA JWKS."
          : "The NRAS device EAT does not validate against the NVIDIA JWKS.",
        domain: "nvidia",
        id: `nvidia-online-device-signature-${result.index}`,
        jsonPath: "$.nvidia_payload",
        label: "Verify NVIDIA device EAT signature",
        severity: "advisory",
        source: "online",
        status: result.signatureValid ? "pass" : "fail",
      }),
    );
  }

  const everyJwtVerified =
    overallSignatureValid && deviceJwtResults.every((result) => result.signatureValid);
  if (!everyJwtVerified) {
    return { checks, status: "partial" };
  }

  checks.push(
    buildCheck({
      description:
        tokenBundle.deviceTokens.length === evidenceCount
          ? "NRAS returned one device EAT for each submitted evidence entry."
          : "NRAS did not return one device EAT per submitted evidence entry.",
      details: [
        buildDetail("Device EAT count", tokenBundle.deviceTokens.length),
        buildDetail("Evidence count", evidenceCount),
      ],
      domain: "nvidia",
      id: "nvidia-online-device-count",
      jsonPath: "$.nvidia_payload",
      label: "Count NVIDIA device EATs",
      severity: "advisory",
      source: "online",
      status: tokenBundle.deviceTokens.length === evidenceCount ? "pass" : "fail",
    }),
  );

  if (tokenBundle.deviceTokens.length !== evidenceCount || !overallJwt) {
    return { checks, status: "partial" };
  }

  const overallNonce = normalizeHex(readClaim(overallJwt.payload, "eat_nonce"));
  const overallResult = readBooleanish(
    readClaim(overallJwt.payload, "x-nvidia-overall-att-result"),
  );
  checks.push(
    buildCheck({
      description:
        expectedNonce && overallNonce === expectedNonce
          ? "The NRAS overall EAT is bound to the requested nonce."
          : "The NRAS overall EAT is not bound to the requested nonce.",
      details: [
        buildDetail("Expected nonce", expectedNonce),
        buildDetail("NRAS overall nonce", overallNonce),
      ],
      domain: "nvidia",
      id: "nvidia-online-overall-nonce",
      jsonPath: "$.nvidia_payload",
      label: "Check NVIDIA overall EAT nonce",
      severity: "blocking",
      source: "online",
      status: expectedNonce && overallNonce === expectedNonce ? "pass" : "fail",
    }),
  );
  checks.push(
    buildCheck({
      description:
        overallResult === true
          ? "The NRAS overall EAT reports a successful attestation result."
          : "The NRAS overall EAT does not report a successful attestation result.",
      domain: "nvidia",
      id: "nvidia-online-overall-result",
      jsonPath: "$.nvidia_payload",
      label: "Check NVIDIA overall EAT result",
      severity: "blocking",
      source: "online",
      status: overallResult === true ? "pass" : "fail",
    }),
  );

  for (const result of deviceJwtResults) {
    const payloadClaims = result.decoded?.payload;
    const deviceNonce = normalizeHex(readClaim(payloadClaims, "eat_nonce"));
    const nonceMatch = readBooleanish(
      readClaim(payloadClaims, "x-nvidia-gpu-attestation-report-nonce-match"),
    );
    const signatureVerified = readBooleanish(
      readClaim(payloadClaims, "x-nvidia-gpu-attestation-report-signature-verified"),
    );
    const certChainStatus = readNestedString(
      payloadClaims,
      "x-nvidia-gpu-attestation-report-cert-chain",
      "x-nvidia-cert-status",
      "x-nvidia-cert-chain-status",
    );
    const archCheck = readBooleanish(
      readClaim(payloadClaims, "x-nvidia-gpu-arch-check"),
    );
    const measurementResult = readClaim(payloadClaims, "measres");

    checks.push(
      buildCheck({
        description:
          expectedNonce && deviceNonce === expectedNonce
            ? "The NRAS device EAT is bound to the requested nonce."
            : "The NRAS device EAT is not bound to the requested nonce.",
        details: [
          buildDetail("Expected nonce", expectedNonce),
          buildDetail("Device nonce", deviceNonce),
        ],
        domain: "nvidia",
        id: `nvidia-online-device-nonce-${result.index}`,
        jsonPath: "$.nvidia_payload",
        label: "Check NVIDIA device EAT nonce",
        severity: "blocking",
        source: "online",
        status: expectedNonce && deviceNonce === expectedNonce ? "pass" : "fail",
      }),
    );

    checks.push(
      buildCheck({
        description:
          nonceMatch === true
            ? "NRAS reports that the GPU attestation report nonce matched."
            : "NRAS does not report a matching GPU attestation report nonce.",
        domain: "nvidia",
        id: `nvidia-online-device-claim-nonce-${result.index}`,
        jsonPath: "$.nvidia_payload",
        label: "Inspect NVIDIA nonce-match claim",
        severity: "blocking",
        source: "online",
        status: nonceMatch === true ? "pass" : "fail",
      }),
    );

    checks.push(
      buildCheck({
        description:
          signatureVerified === true
            ? "NRAS reports that the GPU attestation report signature verified."
            : "NRAS does not report a verified GPU attestation report signature.",
        domain: "nvidia",
        id: `nvidia-online-device-claim-signature-${result.index}`,
        jsonPath: "$.nvidia_payload",
        label: "Inspect NVIDIA signature-verification claim",
        severity: "blocking",
        source: "online",
        status: signatureVerified === true ? "pass" : "fail",
      }),
    );

    checks.push(
      buildCheck({
        description:
          certChainStatus === "valid"
            ? "NRAS reports a valid NVIDIA device certificate chain."
            : "NRAS does not report a valid NVIDIA device certificate chain.",
        details: [buildDetail("NRAS certificate-chain status", certChainStatus)],
        domain: "nvidia",
        id: `nvidia-online-device-claim-cert-chain-${result.index}`,
        jsonPath: "$.nvidia_payload",
        label: "Inspect NVIDIA certificate-chain claim",
        severity: "blocking",
        source: "online",
        status: certChainStatus === "valid" ? "pass" : "fail",
      }),
    );

    checks.push(
      buildCheck({
        description:
          archCheck === undefined
            ? "The NRAS device EAT did not include an explicit architecture check claim."
            : archCheck
              ? "NRAS reports a successful GPU architecture check."
              : "NRAS reports a failed GPU architecture check.",
        details: [buildDetail("Expected architecture", expectedArch)],
        domain: "nvidia",
        id: `nvidia-online-device-claim-arch-${result.index}`,
        jsonPath: "$.nvidia_payload",
        label: "Inspect NVIDIA architecture claim",
        severity: "blocking",
        source: "online",
        status: archCheck === undefined || archCheck ? "pass" : "fail",
      }),
    );

    checks.push(
      buildCheck({
        description:
          measurementResult === undefined
            ? "The NRAS device EAT did not include a measurement result claim."
            : String(measurementResult).toLowerCase() === "success"
              ? "NRAS reports a successful GPU measurement result."
              : "NRAS does not report a successful GPU measurement result.",
        details: [buildDetail("NRAS measurement result", measurementResult)],
        domain: "nvidia",
        id: `nvidia-online-device-claim-measurement-${result.index}`,
        jsonPath: "$.nvidia_payload",
        label: "Inspect NVIDIA measurement claim",
        severity: "blocking",
        source: "online",
        status:
          measurementResult === undefined ||
          String(measurementResult).toLowerCase() === "success"
            ? "pass"
            : "fail",
      }),
    );
  }

  return {
    checks,
    status: hasBlockingFailures(checks) ? "partial" : "verified",
  };
}

async function fetchIntelJson<T>({
  fetchImpl,
  headerName,
  id,
  jsonPath,
  label,
  parser,
  url,
}: {
  fetchImpl: typeof fetch;
  headerName: string;
  id: string;
  jsonPath: string;
  label: string;
  parser: (value: unknown) => T | undefined;
  url: string;
}): Promise<
  | { checks: CheckResult[]; ok: false }
  | { checks: CheckResult[]; issuerChain: string; ok: true; value: T }
> {
  const response = await fetchJson({
    fetchImpl,
    id,
    jsonPath,
    label,
    url,
  });
  if (!response.ok) {
    return response;
  }

  const parsed = parser(response.value);
  const issuerChain = decodeIssuerChainHeader(response.headers.get(headerName));
  const checks = [...response.checks];

  checks.push(
    buildCheck({
      description: parsed
        ? `${label} returned the expected Intel collateral shape.`
        : `${label} did not return the expected Intel collateral shape.`,
      domain: "tdx",
      id: `${id}-shape`,
      jsonPath,
      label: `Inspect ${label.toLowerCase()} response`,
      severity: "advisory",
      source: "online",
      status: parsed ? "pass" : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description: issuerChain
        ? `${label} included its issuer chain header.`
        : `${label} did not include its issuer chain header.`,
      domain: "tdx",
      id: `${id}-issuer-chain`,
      jsonPath,
      label: `Read ${label.toLowerCase()} issuer chain`,
      severity: "advisory",
      source: "online",
      status: issuerChain ? "pass" : "fail",
    }),
  );

  if (!parsed || !issuerChain) {
    return { checks, ok: false };
  }

  return {
    checks,
    issuerChain,
    ok: true,
    value: parsed,
  };
}

async function fetchIntelText({
  fetchImpl,
  headerName,
  id,
  jsonPath,
  label,
  url,
}: {
  fetchImpl: typeof fetch;
  headerName: string;
  id: string;
  jsonPath: string;
  label: string;
  url: string;
}): Promise<
  | { checks: CheckResult[]; ok: false }
  | { checks: CheckResult[]; issuerChain: string; ok: true; value: string }
> {
  const response = await fetchText({
    fetchImpl,
    id,
    jsonPath,
    label,
    url,
  });
  if (!response.ok) {
    return response;
  }

  const issuerChain = decodeIssuerChainHeader(response.headers.get(headerName));
  const pemLike = response.value.includes("BEGIN X509 CRL");
  const checks = [...response.checks];

  checks.push(
    buildCheck({
      description: pemLike
        ? `${label} returned a PEM-encoded CRL.`
        : `${label} did not return a PEM-encoded CRL.`,
      domain: "tdx",
      id: `${id}-shape`,
      jsonPath,
      label: `Inspect ${label.toLowerCase()} response`,
      severity: "advisory",
      source: "online",
      status: pemLike ? "pass" : "fail",
    }),
  );

  checks.push(
    buildCheck({
      description: issuerChain
        ? `${label} included its issuer chain header.`
        : `${label} did not include its issuer chain header.`,
      domain: "tdx",
      id: `${id}-issuer-chain`,
      jsonPath,
      label: `Read ${label.toLowerCase()} issuer chain`,
      severity: "advisory",
      source: "online",
      status: issuerChain ? "pass" : "fail",
    }),
  );

  if (!pemLike || !issuerChain) {
    return { checks, ok: false };
  }

  return {
    checks,
    issuerChain,
    ok: true,
    value: response.value,
  };
}

async function fetchJson({
  fetchImpl,
  id,
  jsonPath,
  label,
  url,
}: {
  fetchImpl: typeof fetch;
  id: string;
  jsonPath: string;
  label: string;
  url: string;
}): Promise<
  | { checks: CheckResult[]; ok: false }
  | {
      checks: CheckResult[];
      headers: Headers;
      ok: true;
      value: unknown;
    }
> {
  try {
    const response = await fetchImpl(url, {
      headers: {
        accept: "application/json",
      },
    });

    const checks: CheckResult[] = [
      buildCheck({
        description: response.ok
          ? `${label} completed with HTTP ${response.status}.`
          : `${label} failed with HTTP ${response.status}.`,
        details: [
          buildDetail("URL", url),
          buildDetail("HTTP status", response.status),
        ],
        domain: jsonPath === "$.nvidia_payload" ? "nvidia" : "tdx",
        id,
        jsonPath,
        label,
        severity: "advisory",
        source: "online",
        status: response.ok ? "pass" : "fail",
      }),
    ];

    if (!response.ok) {
      return { checks, ok: false };
    }

    const bodyText = await response.text();
    try {
      return {
        checks,
        headers: response.headers,
        ok: true,
        value: JSON.parse(bodyText),
      };
    } catch {
      checks.push(
        buildCheck({
          description: `${label} returned a non-JSON body.`,
          domain: jsonPath === "$.nvidia_payload" ? "nvidia" : "tdx",
          id: `${id}-json`,
          jsonPath,
          label: `Decode ${label.toLowerCase()} JSON`,
          severity: "advisory",
          source: "online",
          status: "fail",
        }),
      );
      return { checks, ok: false };
    }
  } catch (error) {
    return {
      checks: [
        buildCheck({
          description:
            error instanceof Error
              ? `${label} could not be fetched: ${error.message}`
              : `${label} could not be fetched.`,
          details: [buildDetail("URL", url)],
          domain: jsonPath === "$.nvidia_payload" ? "nvidia" : "tdx",
          id,
          jsonPath,
          label,
          severity: "advisory",
          source: "online",
          status: "fail",
        }),
      ],
      ok: false,
    };
  }
}

async function fetchText({
  fetchImpl,
  id,
  jsonPath,
  label,
  url,
}: {
  fetchImpl: typeof fetch;
  id: string;
  jsonPath: string;
  label: string;
  url: string;
}): Promise<
  | { checks: CheckResult[]; ok: false }
  | { checks: CheckResult[]; headers: Headers; ok: true; value: string }
> {
  try {
    const response = await fetchImpl(url, {
      headers: {
        accept: "application/x-pem-file, text/plain, application/json",
      },
    });

    const checks: CheckResult[] = [
      buildCheck({
        description: response.ok
          ? `${label} completed with HTTP ${response.status}.`
          : `${label} failed with HTTP ${response.status}.`,
        details: [
          buildDetail("URL", url),
          buildDetail("HTTP status", response.status),
        ],
        domain: "tdx",
        id,
        jsonPath,
        label,
        severity: "advisory",
        source: "online",
        status: response.ok ? "pass" : "fail",
      }),
    ];

    if (!response.ok) {
      return { checks, ok: false };
    }

    return {
      checks,
      headers: response.headers,
      ok: true,
      value: await response.text(),
    };
  } catch (error) {
    return {
      checks: [
        buildCheck({
          description:
            error instanceof Error
              ? `${label} could not be fetched: ${error.message}`
              : `${label} could not be fetched.`,
          details: [buildDetail("URL", url)],
          domain: "tdx",
          id,
          jsonPath,
          label,
          severity: "advisory",
          source: "online",
          status: "fail",
        }),
      ],
      ok: false,
    };
  }
}

async function verifyIntelPckCrl({
  crlPem,
  issuerChain,
  pckLeaf,
}: {
  crlPem: string;
  issuerChain: X509Certificate[];
  pckLeaf?: X509Certificate;
}): Promise<{
  checks: CheckResult[];
  complete: boolean;
}> {
  const checks: CheckResult[] = [];

  if (!pckLeaf || !issuerChain[0]) {
    checks.push(
      buildCheck({
        description:
          "The Intel PCK CRL could not be checked because the PCK leaf or CRL issuer certificate was unavailable.",
        domain: "tdx",
        id: "intel-online-pck-crl-support",
        jsonPath: "$.intel_quote",
        label: "Prepare Intel PCK CRL verification",
        severity: "advisory",
        source: "online",
        status: "fail",
      }),
    );

    return { checks, complete: false };
  }

  let crl: X509Crl;
  try {
    crl = new X509Crl(crlPem);
  } catch (error) {
    checks.push(
      buildCheck({
        description:
          error instanceof Error
            ? `The Intel PCK CRL could not be parsed: ${error.message}`
            : "The Intel PCK CRL could not be parsed.",
        domain: "tdx",
        id: "intel-online-pck-crl-parse",
        jsonPath: "$.intel_quote",
        label: "Parse Intel PCK CRL",
        severity: "advisory",
        source: "online",
        status: "fail",
      }),
    );

    return { checks, complete: false };
  }

  checks.push(
    buildCheck({
      description: "The Intel PCK CRL parsed successfully.",
      domain: "tdx",
      id: "intel-online-pck-crl-parse",
      jsonPath: "$.intel_quote",
      label: "Parse Intel PCK CRL",
      severity: "advisory",
      source: "online",
      status: "pass",
    }),
  );

  const signatureValid = await crl.verify({ publicKey: issuerChain[0] });
  checks.push(
    buildCheck({
      description: signatureValid
        ? "The Intel PCK CRL signature validates against the issuer certificate."
        : "The Intel PCK CRL signature does not validate against the issuer certificate.",
      domain: "tdx",
      id: "intel-online-pck-crl-signature",
      jsonPath: "$.intel_quote",
      label: "Verify Intel PCK CRL signature",
      severity: "advisory",
      source: "online",
      status: signatureValid ? "pass" : "fail",
    }),
  );

  const now = Date.now();
  const fresh =
    crl.thisUpdate.getTime() <= now &&
    (crl.nextUpdate === undefined || crl.nextUpdate.getTime() >= now);
  checks.push(
    buildCheck({
      description: fresh
        ? "The Intel PCK CRL is within its validity window."
        : "The Intel PCK CRL is outside its validity window.",
      domain: "tdx",
      id: "intel-online-pck-crl-validity",
      jsonPath: "$.intel_quote",
      label: "Check Intel PCK CRL freshness",
      severity: "advisory",
      source: "online",
      status: fresh ? "pass" : "fail",
    }),
  );

  if (!signatureValid || !fresh) {
    return { checks, complete: false };
  }

  const revoked = crl.findRevoked(pckLeaf) !== null;
  checks.push(
    buildCheck({
      description: revoked
        ? "The Intel PCK leaf certificate appears in the live Intel PCK CRL."
        : "The Intel PCK leaf certificate does not appear in the live Intel PCK CRL.",
      details: [
        buildDetail("PCK leaf serial number", pckLeaf.serialNumber),
        buildDetail("CRL issuer", crl.issuer),
      ],
      domain: "tdx",
      id: "intel-online-pck-revocation",
      jsonPath: "$.intel_quote",
      label: "Check Intel PCK certificate revocation",
      severity: "blocking",
      source: "online",
      status: revoked ? "fail" : "pass",
    }),
  );

  return { checks, complete: true };
}

async function evaluateIntelSigningChainRevocation({
  certificates,
  fetchImpl,
}: {
  certificates: X509Certificate[];
  fetchImpl: typeof fetch;
}): Promise<{
  checks: CheckResult[];
  complete: boolean;
}> {
  const checks: CheckResult[] = [];
  let complete = true;

  for (let index = 0; index < Math.max(0, certificates.length - 1); index += 1) {
    const certificate = certificates[index];
    const issuer = certificates[index + 1];
    const crlUrls = extractCrlUrls(certificate);

    checks.push(
      buildCheck({
        description:
          crlUrls.length > 0
            ? "The Intel issuer certificate exposes CRL distribution points."
            : "The Intel issuer certificate does not expose CRL distribution points.",
        details: [buildDetail("CRL URLs", crlUrls.join(", "))],
        domain: "tdx",
        id: `intel-online-signing-cert-crl-urls-${index}`,
        jsonPath: "$.intel_quote",
        label: "Inspect Intel signing certificate revocation URLs",
        severity: "advisory",
        source: "online",
        status: crlUrls.length > 0 ? "pass" : "info",
      }),
    );

    if (!issuer || crlUrls.length === 0) {
      continue;
    }

    const crlFetchResult = await fetchFirstCrl({
      fetchImpl,
      label: "Fetch Intel signing certificate CRL",
      urls: crlUrls,
    });
    checks.push(...crlFetchResult.checks.map((check, checkIndex) => ({
      ...check,
      id: `${check.id}-${index}-${checkIndex}`,
    })));

    if (!crlFetchResult.ok) {
      complete = false;
      continue;
    }

    let crl: X509Crl;
    try {
      crl = new X509Crl(crlFetchResult.pem);
    } catch (error) {
      complete = false;
      checks.push(
        buildCheck({
          description:
            error instanceof Error
              ? `The Intel signing certificate CRL could not be parsed: ${error.message}`
              : "The Intel signing certificate CRL could not be parsed.",
          domain: "tdx",
          id: `intel-online-signing-cert-crl-parse-${index}`,
          jsonPath: "$.intel_quote",
          label: "Parse Intel signing certificate CRL",
          severity: "advisory",
          source: "online",
          status: "fail",
        }),
      );
      continue;
    }

    checks.push(
      buildCheck({
        description: "The Intel signing certificate CRL parsed successfully.",
        domain: "tdx",
        id: `intel-online-signing-cert-crl-parse-${index}`,
        jsonPath: "$.intel_quote",
        label: "Parse Intel signing certificate CRL",
        severity: "advisory",
        source: "online",
        status: "pass",
      }),
    );

    const signatureValid = await crl.verify({ publicKey: issuer });
    checks.push(
      buildCheck({
        description: signatureValid
          ? "The Intel signing certificate CRL signature validates against the issuer certificate."
          : "The Intel signing certificate CRL signature does not validate against the issuer certificate.",
        domain: "tdx",
        id: `intel-online-signing-cert-crl-signature-${index}`,
        jsonPath: "$.intel_quote",
        label: "Verify Intel signing certificate CRL signature",
        severity: "advisory",
        source: "online",
        status: signatureValid ? "pass" : "fail",
      }),
    );

    const now = Date.now();
    const fresh =
      crl.thisUpdate.getTime() <= now &&
      (crl.nextUpdate === undefined || crl.nextUpdate.getTime() >= now);
    checks.push(
      buildCheck({
        description: fresh
          ? "The Intel signing certificate CRL is within its validity window."
          : "The Intel signing certificate CRL is outside its validity window.",
        domain: "tdx",
        id: `intel-online-signing-cert-crl-validity-${index}`,
        jsonPath: "$.intel_quote",
        label: "Check Intel signing certificate CRL freshness",
        severity: "advisory",
        source: "online",
        status: fresh ? "pass" : "fail",
      }),
    );

    if (!signatureValid || !fresh) {
      complete = false;
      continue;
    }

    const revoked = crl.findRevoked(certificate) !== null;
    checks.push(
      buildCheck({
        description: revoked
          ? "The Intel signing certificate appears in its CRL."
          : "The Intel signing certificate does not appear in its CRL.",
        details: [buildDetail("Certificate subject", certificate.subject)],
        domain: "tdx",
        id: `intel-online-signing-cert-revocation-${index}`,
        jsonPath: "$.intel_quote",
        label: "Check Intel signing certificate revocation",
        severity: "blocking",
        source: "online",
        status: revoked ? "fail" : "pass",
      }),
    );
  }

  return {
    checks,
    complete,
  };
}

async function fetchFirstCrl({
  fetchImpl,
  label,
  urls,
}: {
  fetchImpl: typeof fetch;
  label: string;
  urls: string[];
}): Promise<
  | { checks: CheckResult[]; ok: false }
  | { checks: CheckResult[]; ok: true; pem: string }
> {
  const checks: CheckResult[] = [];

  for (const url of urls) {
    const result = await fetchText({
      fetchImpl,
      id: "intel-online-generic-crl-fetch",
      jsonPath: "$.intel_quote",
      label,
      url,
    });
    checks.push(...result.checks);

    if (!result.ok) {
      continue;
    }

    return {
      checks,
      ok: true,
      pem: result.value,
    };
  }

  return {
    checks,
    ok: false,
  };
}

async function fetchNrasAttestation({
  apiKey,
  baseUrl,
  fetchImpl,
  payload,
}: {
  apiKey?: string;
  baseUrl: string;
  fetchImpl: typeof fetch;
  payload: Record<string, unknown>;
}): Promise<
  | { checks: CheckResult[]; ok: false }
  | { checks: CheckResult[]; ok: true; value: unknown }
> {
  try {
    const attempts = buildNrasAuthAttempts(apiKey);
    const url = `${baseUrl}/attest/gpu`;

    for (const [attemptIndex, attempt] of attempts.entries()) {
      const headers = new Headers({
        accept: "application/json",
        "content-type": "application/json",
      });

      if (attempt.headerName && attempt.headerValue) {
        headers.set(attempt.headerName, attempt.headerValue);
      }

      const response = await fetchImpl(url, {
        body: JSON.stringify(payload),
        headers,
        method: "POST",
      });
      const bodyText = await response.text();
      const bodySnippet = summarizeResponseBody(bodyText);
      const usedFallback = attemptIndex > 0;
      const checks: CheckResult[] = [
        buildCheck({
          description: response.ok
            ? `The NVIDIA NRAS request completed with HTTP ${response.status}.`
            : `The NVIDIA NRAS request failed with HTTP ${response.status}.`,
          details: [
            buildDetail("NRAS URL", url),
            buildDetail("Authentication scheme", attempt.label),
            buildDetail("HTTP status", response.status),
            buildDetail("Retry fallback", usedFallback),
            buildDetail("Response body", bodySnippet),
          ],
          domain: "nvidia",
          id: "nvidia-online-attest-fetch",
          jsonPath: "$.nvidia_payload",
          label: "Submit NVIDIA evidence to NRAS",
          severity: "advisory",
          source: "online",
          status: response.ok ? "pass" : "fail",
        }),
      ];

      if (!response.ok) {
        const shouldRetry =
          attemptIndex < attempts.length - 1 &&
          response.status >= 401 &&
          response.status <= 403;
        if (shouldRetry) {
          continue;
        }

        return { checks, ok: false };
      }

      if (usedFallback) {
        checks.push(
          buildCheck({
            description: `NRAS accepted the NVIDIA API key after retrying with the ${attempt.label} scheme.`,
            details: [
              buildDetail(
                "Tried schemes",
                attempts
                  .slice(0, attemptIndex + 1)
                  .map((entry) => entry.label)
                  .join(", "),
              ),
            ],
            domain: "nvidia",
            id: "nvidia-online-auth-scheme",
            jsonPath: "$.nvidia_payload",
            label: "Resolve NVIDIA API key auth scheme",
            severity: "advisory",
            source: "online",
            status: "pass",
          }),
        );
      }

      try {
        return {
          checks,
          ok: true,
          value: JSON.parse(bodyText),
        };
      } catch {
        checks.push(
          buildCheck({
            description:
              "The NVIDIA NRAS response did not decode as JSON.",
            domain: "nvidia",
            id: "nvidia-online-attest-json",
            jsonPath: "$.nvidia_payload",
            label: "Decode NVIDIA NRAS response",
            severity: "advisory",
            source: "online",
            status: "fail",
          }),
        );
        return { checks, ok: false };
      }
    }

    return {
      checks: [
        buildCheck({
          description:
            "The NVIDIA NRAS request could not determine a working authentication scheme for the supplied API key.",
          domain: "nvidia",
          id: "nvidia-online-attest-fetch",
          jsonPath: "$.nvidia_payload",
          label: "Submit NVIDIA evidence to NRAS",
          severity: "advisory",
          source: "online",
          status: "fail",
        }),
      ],
      ok: false,
    };
  } catch (error) {
    return {
      checks: [
        buildCheck({
          description:
            error instanceof Error
              ? `The NVIDIA NRAS request could not be completed: ${error.message}`
              : "The NVIDIA NRAS request could not be completed.",
          domain: "nvidia",
          id: "nvidia-online-attest-fetch",
          jsonPath: "$.nvidia_payload",
          label: "Submit NVIDIA evidence to NRAS",
          severity: "advisory",
          source: "online",
          status: "fail",
        }),
      ],
      ok: false,
    };
  }
}

type NrasAuthAttempt = {
  headerName?: string;
  headerValue?: string;
  label: string;
};

function buildNrasAuthAttempts(apiKey?: string): NrasAuthAttempt[] {
  const normalizedKey = apiKey?.trim();
  if (!normalizedKey) {
    return [{ label: "none" }];
  }

  const keyLooksLikeNvApi = normalizedKey.startsWith("nvapi-");
  if (keyLooksLikeNvApi) {
    return [
      {
        headerName: "authorization",
        headerValue: normalizedKey,
        label: "raw authorization",
      },
      {
        headerName: "x-api-key",
        headerValue: normalizedKey,
        label: "x-api-key",
      },
      {
        headerName: "authorization",
        headerValue: `Bearer ${normalizedKey}`,
        label: "bearer token",
      },
    ];
  }

  return [
    {
      headerName: "authorization",
      headerValue: `Bearer ${normalizedKey}`,
      label: "bearer token",
    },
    {
      headerName: "authorization",
      headerValue: normalizedKey,
      label: "raw authorization",
    },
    {
      headerName: "x-api-key",
      headerValue: normalizedKey,
      label: "x-api-key",
    },
  ];
}

function summarizeResponseBody(value: string): string {
  if (value.trim().length === 0) {
    return "empty";
  }

  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length > 240
    ? `${normalized.slice(0, 237)}...`
    : normalized;
}

type DecodedJwt = {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
};

function decodeJwt(token: string): DecodedJwt | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return undefined;
  }

  try {
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const headerValue = JSON.parse(base64UrlToUtf8(encodedHeader));
    const payloadValue = JSON.parse(base64UrlToUtf8(encodedPayload));

    if (!isRecord(headerValue) || !isRecord(payloadValue)) {
      return undefined;
    }

    return {
      header: headerValue,
      payload: payloadValue,
      signature: base64UrlToBytes(encodedSignature),
      signingInput: `${encodedHeader}.${encodedPayload}`,
    };
  } catch {
    return undefined;
  }
}

async function verifyJwtSignature({
  jwks,
  token,
}: {
  jwks: JsonWebKey[];
  token: string;
}): Promise<boolean> {
  const decoded = decodeJwt(token);
  if (!decoded) {
    return false;
  }

  const algorithm = mapJwtAlgorithm(decoded.header.alg);
  if (!algorithm) {
    return false;
  }

  const key = selectJwk(jwks, decoded.header.kid, algorithm.namedCurve);
  if (!key) {
    return false;
  }

  try {
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      key,
      {
        name: "ECDSA",
        namedCurve: algorithm.namedCurve,
      },
      false,
      ["verify"],
    );

    return verifyEcdsaSignature({
      hash: algorithm.hash,
      namedCurve: algorithm.namedCurve,
      payload: utf8ToBytes(decoded.signingInput),
      publicKey: cryptoKey,
      signature: decoded.signature,
      signatureFormat: "ieee-p1363",
    });
  } catch {
    return false;
  }
}

function mapJwtAlgorithm(
  value: unknown,
):
  | { hash: "SHA-256" | "SHA-384" | "SHA-512"; namedCurve: "P-256" | "P-384" | "P-521" }
  | undefined {
  if (value === "ES256") {
    return { hash: "SHA-256", namedCurve: "P-256" };
  }

  if (value === "ES384") {
    return { hash: "SHA-384", namedCurve: "P-384" };
  }

  if (value === "ES512") {
    return { hash: "SHA-512", namedCurve: "P-521" };
  }

  return undefined;
}

function selectJwk(
  jwks: JsonWebKey[],
  kid: unknown,
  namedCurve: "P-256" | "P-384" | "P-521",
): JsonWebKey | undefined {
  const normalizedKid = typeof kid === "string" ? kid : undefined;

  return jwks.find((entry) => {
    if (entry.kty !== "EC") {
      return false;
    }

    if (entry.crv !== namedCurve) {
      return false;
    }

    const entryKid =
      isRecord(entry) && typeof entry.kid === "string" ? entry.kid : undefined;

    return normalizedKid ? entryKid === normalizedKid : true;
  });
}

function extractNrasTokenBundle(value: unknown): {
  deviceTokens: string[];
  overallToken?: string;
} {
  if (isRecord(value) && Array.isArray(value.detached_eat)) {
    const detachedEat = value.detached_eat;
    const overallToken = extractJwt(detachedEat[0]);
    const deviceTokens = extractDetachedDeviceTokens(detachedEat[1]);
    return {
      deviceTokens,
      overallToken,
    };
  }

  const tokens = collectJwtStrings(value);
  return {
    deviceTokens: tokens.slice(1),
    overallToken: tokens[0],
  };
}

function extractDetachedDeviceTokens(value: unknown): string[] {
  if (!isRecord(value)) {
    return [];
  }

  return Object.values(value)
    .map((entry) => extractJwt(entry))
    .filter((entry): entry is string => typeof entry === "string");
}

function extractJwt(value: unknown): string | undefined {
  if (typeof value === "string") {
    return looksLikeJwt(value) ? value : undefined;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const token = extractJwt(item);
      if (token) {
        return token;
      }
    }
  }

  if (isRecord(value)) {
    for (const item of Object.values(value)) {
      const token = extractJwt(item);
      if (token) {
        return token;
      }
    }
  }

  return undefined;
}

function collectJwtStrings(value: unknown): string[] {
  const tokens: string[] = [];

  if (typeof value === "string") {
    if (looksLikeJwt(value)) {
      tokens.push(value);
    }
    return tokens;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      tokens.push(...collectJwtStrings(item));
    }
    return tokens;
  }

  if (isRecord(value)) {
    for (const item of Object.values(value)) {
      tokens.push(...collectJwtStrings(item));
    }
  }

  return Array.from(new Set(tokens));
}

function looksLikeJwt(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 3 &&
    parts.every((part) => /^[A-Za-z0-9_-]+$/.test(part) && part.length > 0)
  );
}

function readClaim(payload: unknown, key: string): unknown {
  return isRecord(payload) ? payload[key] : undefined;
}

function readNestedString(
  payload: unknown,
  key: string,
  ...nestedKeys: string[]
): string | undefined {
  if (!isRecord(payload)) {
    return undefined;
  }

  let current: unknown = payload[key];
  for (const nestedKey of nestedKeys) {
    if (!isRecord(current)) {
      return undefined;
    }

    const candidate = current[nestedKey];
    if (typeof candidate === "string") {
      return candidate;
    }
    if (typeof candidate === "boolean") {
      return candidate ? "valid" : "invalid";
    }

    current = candidate;
  }

  return undefined;
}

function readBooleanish(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") {
      return true;
    }
    if (normalized === "false") {
      return false;
    }
  }

  return undefined;
}

function isJwksResponse(value: unknown): value is { keys: JsonWebKey[] } {
  return (
    isRecord(value) &&
    Array.isArray(value.keys) &&
    value.keys.every((entry) => isRecord(entry))
  );
}

function deriveIntelPckCaType(
  chain: X509Certificate[],
): "platform" | "processor" | undefined {
  const issuerHints = [chain[0]?.issuer, chain[1]?.subject]
    .filter((value): value is string => typeof value === "string")
    .join(" ");

  const normalized = issuerHints.toLowerCase();
  if (normalized.includes("processor ca")) {
    return "processor";
  }

  if (normalized.includes("platform ca")) {
    return "platform";
  }

  return undefined;
}

function extractCrlUrls(certificate: X509Certificate): string[] {
  const extension = certificate.getExtension(CRLDistributionPointsExtension);
  if (!extension) {
    return [];
  }

  const textObject = extension.toTextObject();
  const urls = new Set<string>();

  visitTextObject(textObject, (value) => {
    if (typeof value !== "string") {
      return;
    }

    const trimmed = value.trim();
    if (!trimmed.startsWith("URL:")) {
      return;
    }

    urls.add(trimmed.slice(4).trim());
  });

  return Array.from(urls);
}

function visitTextObject(
  value: unknown,
  visitor: (value: unknown) => void,
) {
  visitor(value);

  if (Array.isArray(value)) {
    for (const item of value) {
      visitTextObject(item, visitor);
    }
    return;
  }

  if (isRecord(value)) {
    for (const item of Object.values(value)) {
      visitTextObject(item, visitor);
    }
  }
}

function decodeIssuerChainHeader(value: string | null): string | undefined {
  if (!value || value.trim().length === 0) {
    return undefined;
  }

  try {
    const decoded = decodeURIComponent(value.replace(/\+/g, "%20"));
    return decoded.includes("BEGIN CERTIFICATE") ? decoded : undefined;
  } catch {
    return value.includes("BEGIN CERTIFICATE") ? value : undefined;
  }
}

function resolveFetch(
  value?: typeof fetch,
): typeof fetch | undefined {
  if (value) {
    return value;
  }

  return typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : undefined;
}

function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, "");
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

function base64UrlToUtf8(value: string): string {
  return new TextDecoder().decode(base64UrlToBytes(value));
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");

  return Uint8Array.from(atob(normalized), (char) => char.charCodeAt(0));
}

function hasFailedChecks(checks: CheckResult[]): boolean {
  return checks.some((check) => check.status === "fail");
}

function hasBlockingFailures(checks: CheckResult[]): boolean {
  return checks.some(
    (check) => check.severity === "blocking" && check.status === "fail",
  );
}

function buildCheck(check: CheckResult): CheckResult {
  return check;
}

function buildDetail(label: string, value: unknown) {
  if (value === undefined) {
    return {
      label,
      value: "Unavailable",
    };
  }

  if (typeof value === "string") {
    return {
      copyValue: value,
      label,
      value,
    };
  }

  return {
    label,
    value: String(value),
  };
}
