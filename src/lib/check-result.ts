export type CheckStatus = "pass" | "fail" | "info";

export type CheckResult = {
  id: string;
  label: string;
  status: CheckStatus;
  description: string;
  jsonPath: string;
};
