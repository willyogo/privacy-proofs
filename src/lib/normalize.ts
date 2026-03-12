import type { CheckResult } from "./check-result";
import { parseAttestationReport } from "./schema";
import type {
  ParseResult,
  ReportSummary,
  VerificationSummary,
} from "./types";

export function createIdleParseResult(): ParseResult {
  return {
    state: "idle",
    checks: [],
    verification: {
      badge: "Awaiting input",
      cryptographicStatus: "unsupported",
      description:
        "Paste or upload an attestation report, then run the browser-side verifier.",
      evidenceStatus: {
        intel: "unsupported",
        nvidia: "unsupported",
      },
      engineLabel: "Engine ready",
      failedChecks: 0,
      headline: "Ready to Verify",
      infoChecks: 0,
      mode: "offline",
      passedChecks: 0,
      status: "idle",
      supportedChecks: 0,
    },
  };
}

export async function parseReportSource(
  source: string,
  fileName?: string,
): Promise<ParseResult> {
  if (source.trim().length === 0) {
    return createIdleParseResult();
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(source);
  } catch (error) {
    return buildImmediateErrorResult({
      checks: [
        buildCheck({
          description: "The provided input could not be parsed as JSON.",
          domain: "input",
          id: "json-parse",
          jsonPath: "$",
          label: "Parse JSON",
          severity: "blocking",
          source: "local",
          status: "fail",
        }),
      ],
      errorMessage:
        error instanceof Error ? error.message : "The report is not valid JSON.",
    });
  }

  const normalized = parseAttestationReport(parsed);

  if (!normalized.ok) {
    return buildImmediateErrorResult({
      checks: [
        buildCheck({
          description: "The report decoded into a top-level JSON value.",
          domain: "input",
          id: "json-parse",
          jsonPath: "$",
          label: "Parse JSON",
          severity: "blocking",
          source: "local",
          status: "pass",
        }),
        ...normalized.errors.map((error, index) =>
          buildCheck({
            description: error.message,
            domain: "input",
            id: `schema-${index}`,
            jsonPath: error.path,
            label: "Validate report schema",
            severity: "blocking",
            source: "local",
            status: "fail",
          }),
        ),
      ],
      errorMessage:
        "The report does not match the expected attestation schema. Review the diagnostics for exact field and type failures.",
      parseErrors: normalized.errors,
    });
  }

  const report = normalized.value;
  const checks: CheckResult[] = [
    buildCheck({
      description: "The report decoded into a top-level JSON object.",
      domain: "input",
      id: "json-parse",
      jsonPath: "$",
      label: "Parse JSON",
      severity: "blocking",
      source: "local",
      status: "pass",
    }),
    buildCheck({
      description: "The report matches the typed normalization schema.",
      domain: "input",
      id: "report-schema",
      jsonPath: "$",
      label: "Validate report schema",
      severity: "blocking",
      source: "local",
      status: "pass",
    }),
  ];

  const { verifyNormalizedReport } = await import("./verifier");
  const verificationAnalysis = await verifyNormalizedReport(report);
  checks.push(...verificationAnalysis.checks);
  const summary = buildSummary(report, fileName, verificationAnalysis);
  const verification = buildVerificationSummary({
    checks,
    cryptographicStatus: verificationAnalysis.cryptographicStatus,
    evidenceStatus: verificationAnalysis.evidenceStatus,
    mode: verificationAnalysis.mode,
    verifiedAt: verificationAnalysis.verifiedAt,
  });

  return {
    state: verification.status === "invalid" ? "error" : "loaded",
    errorMessage:
      verification.status === "invalid"
        ? "One or more blocking verification checks failed. Review the diagnostics to see exactly which binding, measurement, certificate, or signature check failed."
        : undefined,
    checks,
    normalizedReport: report,
    summary,
    verification,
  };
}

function buildSummary(
  report: ParseResult["normalizedReport"],
  fileName?: string,
  verificationAnalysis?: {
    derivedSigningAddress?: string;
    quoteReportData?: string;
    verifiedAt?: string;
  },
): ReportSummary {
  const topLevelKeys = report ? Object.keys(report) : [];
  const nvidiaPayload = report?.nvidia_payload;

  return {
    appName: typeof report?.info.app_name === "string" ? report.info.app_name : undefined,
    composeHash:
      typeof report?.info.compose_hash === "string"
        ? report.info.compose_hash
        : undefined,
    derivedSigningAddress: verificationAnalysis?.derivedSigningAddress,
    eventLogCount: Array.isArray(report?.event_log) ? report.event_log.length : undefined,
    eventNames: extractEventNames(report?.event_log ?? []),
    fileName,
    model: typeof report?.model === "string" ? report.model : undefined,
    nvidiaEvidenceCount: Array.isArray(nvidiaPayload?.evidence_list)
      ? nvidiaPayload.evidence_list.length
      : undefined,
    preview: report
      ? {
          model: report.model,
          tee_provider: report.tee_provider,
          tee_hardware: report.tee_hardware,
          signing_address: report.signing_address,
          request_nonce: report.request_nonce,
          verified: report.verified,
          server_verification: report.server_verification,
        }
      : {},
    quoteReportData: verificationAnalysis?.quoteReportData,
    signingAddress:
      typeof report?.signing_address === "string" ? report.signing_address : undefined,
    teeHardware:
      typeof report?.tee_hardware === "string" ? report.tee_hardware : undefined,
    teeProvider:
      typeof report?.tee_provider === "string" ? report.tee_provider : undefined,
    topLevelKeys,
    verifiedAt: verificationAnalysis?.verifiedAt,
  };
}

function buildVerificationSummary({
  checks,
  cryptographicStatus,
  evidenceStatus,
  mode,
  verifiedAt,
}: {
  checks: CheckResult[];
  cryptographicStatus: VerificationSummary["cryptographicStatus"];
  evidenceStatus: VerificationSummary["evidenceStatus"];
  mode: VerificationSummary["mode"];
  verifiedAt?: string;
}): VerificationSummary {
  const supportedChecks = checks.filter((check) => check.status !== "info").length;
  const passedChecks = checks.filter((check) => check.status === "pass").length;
  const failedChecks = checks.filter((check) => check.status === "fail").length;
  const infoChecks = checks.filter((check) => check.status === "info").length;
  const blockingFailures = checks.filter(
    (check) => check.severity === "blocking" && check.status === "fail",
  );

  if (supportedChecks === 0) {
    return createIdleParseResult().verification;
  }

  if (blockingFailures.length > 0) {
    return {
      badge: "Verification failed",
      cryptographicStatus,
      description:
        "A blocking local check failed. Do not treat this report as verified.",
      evidenceStatus,
      engineLabel: "Engine active",
      failedChecks,
      headline: "Verification failed",
      infoChecks,
      mode,
      passedChecks,
      status: "invalid",
      supportedChecks,
      verifiedAt,
    };
  }

  if (cryptographicStatus === "verified") {
    return {
      badge: "Verified",
      cryptographicStatus,
      description:
        "Blocking local structure, binding, certificate, and cryptographic checks passed.",
      evidenceStatus,
      engineLabel: "Engine active",
      failedChecks,
      headline: "Attestation verified",
      infoChecks,
      mode,
      passedChecks,
      status: "verified",
      supportedChecks,
      verifiedAt,
    };
  }

  return {
    badge: "Partially verified",
    cryptographicStatus,
    description:
      "Blocking local checks passed, but the raw report did not contain enough supported evidence to complete every independent verification path.",
    evidenceStatus,
    engineLabel: "Engine active",
    failedChecks,
    headline: "Partial verification",
    infoChecks,
    mode,
    passedChecks,
    status: "partially-verified",
    supportedChecks,
    verifiedAt,
  };
}

function extractEventNames(value: ParseResult["normalizedReport"] extends infer Report
  ? Report extends { event_log: infer EventLog }
    ? EventLog
    : never
  : never): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const names = value
    .map((entry) => {
      if (!entry || typeof entry !== "object") {
        return undefined;
      }

      const event = "event" in entry ? entry.event : undefined;
      return typeof event === "string" && event.trim().length > 0
        ? event.trim()
        : undefined;
    })
    .filter((event): event is string => Boolean(event));

  return Array.from(new Set(names)).slice(0, 8);
}

function buildImmediateErrorResult({
  checks,
  errorMessage,
  parseErrors,
}: {
  checks: CheckResult[];
  errorMessage: string;
  parseErrors?: ParseResult["parseErrors"];
}): ParseResult {
  return {
    state: "error",
    checks,
    errorMessage,
    parseErrors,
    verification: buildVerificationSummary({
      checks,
      cryptographicStatus: "unsupported",
      evidenceStatus: {
        intel: "unsupported",
        nvidia: "unsupported",
      },
      mode: "offline",
    }),
  };
}

function buildCheck(check: CheckResult): CheckResult {
  return check;
}
