export type CheckStatus = "pass" | "fail" | "info";

export type CheckSource = "local" | "online" | "embedded";

export type CheckSeverity = "blocking" | "advisory";

export type CheckAuthority =
  | "cryptographic"
  | "consistency"
  | "vendor"
  | "provenance";

export type EvidenceDomain =
  | "input"
  | "binding"
  | "app-cert"
  | "tdx"
  | "nvidia"
  | "event-log"
  | "provenance";

export type CheckDetail = {
  copyValue?: string;
  label: string;
  value: string;
};

export type CheckResult = {
  authority: CheckAuthority;
  description: string;
  details?: CheckDetail[];
  domain: EvidenceDomain;
  id: string;
  jsonPath: string;
  label: string;
  severity: CheckSeverity;
  source: CheckSource;
  status: CheckStatus;
};
