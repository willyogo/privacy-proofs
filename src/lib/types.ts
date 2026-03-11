import type { CheckResult } from "./check-result";

export type RawAttestationReport = Record<string, unknown>;

export type VerificationStatus =
  | "idle"
  | "verified"
  | "partially-verified"
  | "invalid";

export type VerificationSummary = {
  badge: string;
  description: string;
  engineLabel: string;
  failedChecks: number;
  headline: string;
  infoChecks: number;
  passedChecks: number;
  status: VerificationStatus;
  supportedChecks: number;
  verifiedAt?: string;
};

export type ReportSummary = {
  appName?: string;
  composeHash?: string;
  derivedSigningAddress?: string;
  eventLogCount?: number;
  eventNames: string[];
  fileName?: string;
  model?: string;
  nvidiaEvidenceCount?: number;
  preview: Record<string, unknown>;
  quoteReportData?: string;
  signingAddress?: string;
  teeHardware?: string;
  teeProvider?: string;
  topLevelKeys: string[];
  verifiedAt?: string;
};

export type ParseResult = {
  checks: CheckResult[];
  errorMessage?: string;
  normalizedReport?: RawAttestationReport;
  state: "idle" | "loaded" | "error";
  summary?: ReportSummary;
  verification: VerificationSummary;
};
