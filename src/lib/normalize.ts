import type { CheckResult } from "./check-result";
import { REQUIRED_TOP_LEVEL_FIELDS, isRecord } from "./schema";
import type {
  ParseResult,
  RawAttestationReport,
  ReportSummary,
  VerificationSummary,
} from "./types";
import { verifyNormalizedReport } from "./verifier";

export function createIdleParseResult(): ParseResult {
  return {
    state: "idle",
    checks: [],
    verification: {
      badge: "Awaiting input",
      description:
        "Paste or upload an attestation report to run the browser-side verifier.",
      engineLabel: "Engine ready",
      failedChecks: 0,
      headline: "Ready to verify",
      infoChecks: 0,
      passedChecks: 0,
      status: "idle",
      supportedChecks: 0,
    },
  };
}

export function parseReportSource(
  source: string,
  fileName?: string,
): ParseResult {
  if (source.trim().length === 0) {
    return createIdleParseResult();
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(source);
  } catch (error) {
    return {
      state: "error",
      errorMessage:
        error instanceof Error ? error.message : "The report is not valid JSON.",
      checks: [
        {
          id: "json-parse",
          label: "Parse JSON",
          status: "fail",
          description: "The provided input could not be parsed as JSON.",
          jsonPath: "$",
        },
      ],
      verification: buildVerificationSummary({
        checks: [
          {
            id: "json-parse",
            label: "Parse JSON",
            status: "fail",
            description: "The provided input could not be parsed as JSON.",
            jsonPath: "$",
          },
        ],
      }),
    };
  }

  if (!isRecord(parsed)) {
    return {
      state: "error",
      errorMessage: "The report must be a JSON object at the top level.",
      checks: [
        {
          id: "top-level-object",
          label: "Validate top-level object",
          status: "fail",
          description: "A Venice attestation report should decode to a JSON object.",
          jsonPath: "$",
        },
      ],
      verification: buildVerificationSummary({
        checks: [
          {
            id: "top-level-object",
            label: "Validate top-level object",
            status: "fail",
            description: "A Venice attestation report should decode to a JSON object.",
            jsonPath: "$",
          },
        ],
      }),
    };
  }

  const report = { ...parsed } as RawAttestationReport;
  const checks: CheckResult[] = [
    {
      id: "json-parse",
      label: "Parse JSON",
      status: "pass",
      description: "The report decoded into a top-level JSON object.",
      jsonPath: "$",
    },
  ];

  const missingFields = REQUIRED_TOP_LEVEL_FIELDS.filter(
    (field) => !(field in report),
  );

  checks.push({
    id: "required-fields",
    label: "Check required fields",
    status: missingFields.length === 0 ? "pass" : "fail",
    description:
      missingFields.length === 0
        ? "All Milestone 1 required fields are present."
        : `Missing required fields: ${missingFields.join(", ")}.`,
    jsonPath: "$",
  });

  const normalizedNvidiaPayload = normalizeNvidiaPayload(report.nvidia_payload);

  if (normalizedNvidiaPayload.ok) {
    if (normalizedNvidiaPayload.value) {
      report.nvidia_payload = normalizedNvidiaPayload.value;
    }

    checks.push({
      id: "nvidia-payload",
      label: "Decode NVIDIA payload",
      status: "pass",
      description: "The NVIDIA payload is available as structured JSON.",
      jsonPath: "$.nvidia_payload",
    });
  } else {
    checks.push({
      id: "nvidia-payload",
      label: "Decode NVIDIA payload",
      status: "fail",
      description: normalizedNvidiaPayload.error,
      jsonPath: "$.nvidia_payload",
    });
  }

  const eventLogCount = Array.isArray(report.event_log)
    ? report.event_log.length
    : undefined;

  checks.push({
    id: "event-log-shape",
    label: "Inspect event log",
    status: eventLogCount !== undefined ? "pass" : "fail",
    description:
      eventLogCount !== undefined
        ? `The report contains ${eventLogCount} event log entries.`
        : "The report is missing a valid array at $.event_log.",
    jsonPath: "$.event_log",
  });

  const infoObject = isRecord(report.info) ? report.info : undefined;

  checks.push({
    id: "info-shape",
    label: "Inspect info block",
    status: infoObject ? "pass" : "fail",
    description: infoObject
      ? "The info block is available for metadata extraction."
      : "The report is missing a valid object at $.info.",
    jsonPath: "$.info",
  });

  const verificationAnalysis = verifyNormalizedReport(report);
  checks.push(...verificationAnalysis.checks);
  const summary = buildSummary(report, fileName, verificationAnalysis);
  const verification = buildVerificationSummary({
    checks,
    embeddedClaimsAvailable: verificationAnalysis.embeddedClaimsAvailable,
    embeddedClaimsPassed: verificationAnalysis.embeddedClaimsPassed,
    verifiedAt: verificationAnalysis.verifiedAt,
  });

  return {
    state: verification.status === "invalid" ? "error" : "loaded",
    errorMessage:
      verification.status === "invalid"
        ? "One or more verification checks failed. Review the diagnostics to see exactly what was inconsistent."
        : undefined,
    checks,
    normalizedReport: report,
    summary,
    verification,
  };
}

function normalizeNvidiaPayload(value: unknown):
  | { ok: true; value?: Record<string, unknown> }
  | { ok: false; error: string } {
  if (isRecord(value)) {
    return { ok: true, value };
  }

  if (typeof value !== "string") {
    return {
      ok: false,
      error: "Expected $.nvidia_payload to be a JSON string or object.",
    };
  }

  try {
    const parsed = JSON.parse(value);

    if (!isRecord(parsed)) {
      return {
        ok: false,
        error: "The NVIDIA payload decoded, but not into an object.",
      };
    }

    return { ok: true, value: parsed };
  } catch {
    return {
      ok: false,
      error: "The NVIDIA payload could not be decoded as JSON.",
    };
  }
}

function buildSummary(
  report: RawAttestationReport,
  fileName?: string,
  verificationAnalysis?: ReturnType<typeof verifyNormalizedReport>,
): ReportSummary {
  const topLevelKeys = Object.keys(report);
  const infoObject = isRecord(report.info) ? report.info : undefined;
  const nvidiaPayload = isRecord(report.nvidia_payload)
    ? report.nvidia_payload
    : undefined;

  return {
    appName: getString(infoObject?.app_name),
    composeHash: getString(infoObject?.compose_hash),
    eventLogCount: Array.isArray(report.event_log)
      ? report.event_log.length
      : undefined,
    eventNames: extractEventNames(report.event_log),
    fileName,
    model: getString(report.model),
    nvidiaEvidenceCount: Array.isArray(nvidiaPayload?.evidence_list)
      ? nvidiaPayload.evidence_list.length
      : undefined,
    preview: {
      model: report.model,
      tee_provider: report.tee_provider,
      tee_hardware: report.tee_hardware,
      signing_address: report.signing_address,
      request_nonce: report.request_nonce,
      verified: report.verified,
      server_verification: report.server_verification,
    },
    quoteReportData: verificationAnalysis?.quoteReportData,
    derivedSigningAddress: verificationAnalysis?.derivedSigningAddress,
    signingAddress: getString(report.signing_address),
    teeHardware: getString(report.tee_hardware),
    teeProvider: getString(report.tee_provider),
    topLevelKeys,
    verifiedAt: verificationAnalysis?.verifiedAt,
  };
}

function buildVerificationSummary({
  checks,
  embeddedClaimsAvailable,
  embeddedClaimsPassed,
  verifiedAt,
}: {
  checks: CheckResult[];
  embeddedClaimsAvailable?: boolean;
  embeddedClaimsPassed?: boolean;
  verifiedAt?: string;
}): VerificationSummary {
  const supportedChecks = checks.filter((check) => check.status !== "info").length;
  const passedChecks = checks.filter((check) => check.status === "pass").length;
  const failedChecks = checks.filter((check) => check.status === "fail").length;
  const infoChecks = checks.filter((check) => check.status === "info").length;

  if (supportedChecks === 0) {
    return createIdleParseResult().verification;
  }

  if (failedChecks > 0) {
    return {
      badge: "Verification failed",
      description:
        "The verifier found a mismatch in the report structure, bindings, or measurements. The report should not be treated as verified.",
      engineLabel: "Engine active",
      failedChecks,
      headline: "Verification failed",
      infoChecks,
      passedChecks,
      status: "invalid",
      supportedChecks,
      verifiedAt,
    };
  }

  if (embeddedClaimsAvailable && embeddedClaimsPassed) {
    return {
      badge: "Verified",
      description:
        "All supported local checks passed, and the report includes successful embedded TDX and NVIDIA verification claims. This attestation is verified by the current browser engine.",
      engineLabel: "Engine active",
      failedChecks,
      headline: "Attestation verified",
      infoChecks,
      passedChecks,
      status: "verified",
      supportedChecks,
      verifiedAt,
    };
  }

  return {
    badge: "Partially verified",
    description:
      "All supported local bindings passed, but embedded cryptographic verification claims were missing or incomplete. Treat this as a partial verification result.",
    engineLabel: "Engine active",
    failedChecks,
    headline: "Partial verification",
    infoChecks,
    passedChecks,
    status: "partially-verified",
    supportedChecks,
    verifiedAt,
  };
}

function extractEventNames(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const names = value
    .map((entry) => {
      if (!isRecord(entry)) {
        return undefined;
      }

      const event = entry.event;
      return typeof event === "string" && event.trim().length > 0
        ? event.trim()
        : undefined;
    })
    .filter((event): event is string => Boolean(event));

  return Array.from(new Set(names)).slice(0, 8);
}

function getString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
