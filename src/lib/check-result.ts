export type CheckStatus = "pass" | "fail" | "info";

export type CheckSource = "local" | "embedded";

export type CheckSeverity = "blocking" | "advisory";

export type EvidenceDomain =
  | "input"
  | "binding"
  | "app-cert"
  | "tdx"
  | "nvidia"
  | "event-log"
  | "provenance";

export type CheckResult = {
  description: string;
  domain: EvidenceDomain;
  id: string;
  jsonPath: string;
  label: string;
  severity: CheckSeverity;
  source: CheckSource;
  status: CheckStatus;
};
