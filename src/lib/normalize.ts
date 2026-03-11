import type { CheckResult } from "./check-result";
import {
  parseAttestationReport,
  parseCollateralBundle,
} from "./schema";
import type {
  CollateralBundle,
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
      collateralStatus: "not-requested",
      cryptographicStatus: "unsupported",
      description:
        "Paste or upload an attestation report, then run the browser-side verifier.",
      engineLabel: "Engine ready",
      failedChecks: 0,
      headline: "Ready to verify",
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
  collateralSource?: string,
  collateralFileName?: string,
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

  const collateralChecks: CheckResult[] = [];
  let collateralBundle: CollateralBundle | undefined;

  if (collateralSource?.trim()) {
    let parsedCollateral: unknown;

    try {
      parsedCollateral = JSON.parse(collateralSource);
    } catch (error) {
      collateralChecks.push(
        buildCheck({
          description:
            error instanceof Error
              ? `The optional collateral bundle is not valid JSON: ${error.message}`
              : "The optional collateral bundle is not valid JSON.",
          domain: "collateral",
          id: "collateral-json-parse",
          jsonPath: "$",
          label: "Parse collateral bundle",
          severity: "advisory",
          source: "local",
          status: "fail",
        }),
      );
    }

    if (parsedCollateral !== undefined) {
      const parsedBundle = parseCollateralBundle(parsedCollateral);
      if (parsedBundle.ok) {
        collateralBundle = parsedBundle.value;
        collateralChecks.push(
          buildCheck({
            description: "The optional collateral bundle decoded successfully.",
            domain: "collateral",
            id: "collateral-json-parse",
            jsonPath: "$",
            label: "Parse collateral bundle",
            severity: "advisory",
            source: "local",
            status: "pass",
          }),
        );
      } else {
        collateralChecks.push(
          ...parsedBundle.errors.map((error, index) =>
            buildCheck({
              description: error.message,
              domain: "collateral",
              id: `collateral-schema-${index}`,
              jsonPath: error.path,
              label: "Validate collateral bundle schema",
              severity: "advisory",
              source: "local",
              status: "fail",
            }),
          ),
        );
      }
    }
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
        ...collateralChecks,
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
    ...collateralChecks,
  ];

  const { verifyNormalizedReport } = await import("./verifier");
  const verificationAnalysis = await verifyNormalizedReport(report, collateralBundle);
  checks.push(...verificationAnalysis.checks);
  const summary = buildSummary(
    report,
    fileName,
    collateralFileName,
    verificationAnalysis,
  );
  const verification = buildVerificationSummary({
    checks,
    collateralStatus: verificationAnalysis.collateralStatus,
    cryptographicStatus: verificationAnalysis.cryptographicStatus,
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
  collateralFileName?: string,
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
    collateralFileName,
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
  collateralStatus,
  cryptographicStatus,
  mode,
  verifiedAt,
}: {
  checks: CheckResult[];
  collateralStatus: VerificationSummary["collateralStatus"];
  cryptographicStatus: VerificationSummary["cryptographicStatus"];
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
      collateralStatus,
      cryptographicStatus,
      description:
        "A blocking local check failed. Do not treat this report as verified.",
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
      collateralStatus,
      cryptographicStatus,
      description:
        "Blocking local structure, binding, certificate, and cryptographic checks passed.",
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
    collateralStatus,
    cryptographicStatus,
    description:
      "Blocking local checks passed, but the app still lacks all of the collateral or raw-evidence verification needed for a full independent proof.",
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
      collateralStatus: "not-requested",
      cryptographicStatus: "unsupported",
      mode: "offline",
    }),
  };
}

function buildCheck(check: CheckResult): CheckResult {
  return check;
}
