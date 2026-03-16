import type { CheckResult } from "./check-result";

export type VerificationStatus =
  | "idle"
  | "verified"
  | "partially-verified"
  | "invalid";

export type VerificationMode = "offline" | "online";

export type OnlineVerificationOptions = {
  fetchImpl?: typeof fetch;
  intelBaseUrl?: string;
  nvidiaApiKey?: string;
  nvidiaBaseUrl?: string;
  nvidiaJwksUrl?: string;
};

export type ParseReportOptions = {
  mode?: VerificationMode;
  online?: OnlineVerificationOptions;
};

export type CryptographicVerificationStatus =
  | "verified"
  | "partial"
  | "unsupported";

export type EvidenceVerificationStatus =
  | "unsupported"
  | "partial"
  | "verified";

export type EventLogEntry = {
  digest?: string;
  event?: string;
  event_payload?: string;
  event_type?: number;
  imr?: number;
  [key: string]: unknown;
};

export type TcbInfo = {
  app_compose?: string;
  compose_hash?: string;
  device_id?: string;
  event_log?: EventLogEntry[];
  mr_aggregated?: string;
  mrtd?: string;
  os_image_hash?: string;
  rtmr0?: string;
  rtmr1?: string;
  rtmr2?: string;
  rtmr3?: string;
  [key: string]: unknown;
};

export type InfoBlock = {
  app_cert?: string;
  app_id?: string;
  app_name?: string;
  compose_hash?: string;
  device_id?: string;
  instance_id?: string;
  key_provider_info?: Record<string, unknown> | string;
  mr_aggregated?: string;
  os_image_hash?: string;
  tcb_info?: TcbInfo;
  vm_config?: Record<string, unknown> | string;
  [key: string]: unknown;
};

export type NvidiaEvidenceEntry = {
  arch?: string;
  certificate: string;
  evidence: string;
  nonce?: string;
  [key: string]: unknown;
};

export type NvidiaPayload = {
  arch?: string;
  evidence_list: NvidiaEvidenceEntry[];
  nonce?: string;
  [key: string]: unknown;
};

export type ServerVerification = {
  nonceBinding?: Record<string, unknown>;
  nvidia?: Record<string, unknown>;
  nvidiaNonceBinding?: Record<string, unknown>;
  signingAddressBinding?: Record<string, unknown>;
  tdx?: Record<string, unknown>;
  verificationDurationMs?: number;
  verifiedAt?: string;
  [key: string]: unknown;
};

export type IntelQeIdentityLevel = {
  advisoryIDs?: readonly string[];
  tcb: {
    isvsvn: number;
  };
  tcbDate: string;
  tcbStatus: string;
};

export type IntelSignedQeIdentity = {
  enclaveIdentity: {
    attributes: string;
    attributesMask: string;
    id: string;
    isvprodid: number;
    issueDate: string;
    miscselect: string;
    miscselectMask: string;
    mrsigner: string;
    nextUpdate: string;
    tcbEvaluationDataNumber: number;
    tcbLevels: readonly IntelQeIdentityLevel[];
    version: number;
  };
  signature: string;
};

export type IntelTcbComponent = {
  category?: string;
  svn: number;
  type?: string;
};

export type IntelTcbLevel = {
  advisoryIDs?: readonly string[];
  tcb: {
    pcesvn: number;
    sgxtcbcomponents: readonly IntelTcbComponent[];
    tdxtcbcomponents?: readonly IntelTcbComponent[];
  };
  tcbDate: string;
  tcbStatus: string;
};

export type IntelSignedTcbInfo = {
  tcbInfo: {
    fmspc: string;
    id: string;
    issueDate: string;
    nextUpdate: string;
    pceId: string;
    tcbEvaluationDataNumber: number;
    tcbLevels: readonly IntelTcbLevel[];
    tcbType?: number;
    tdxModule?: {
      attributes: string;
      attributesMask: string;
      mrsigner: string;
    };
    version: number;
  };
  signature: string;
};

export type NormalizedAttestationReport = {
  event_log: EventLogEntry[];
  info: InfoBlock;
  intel_quote: string;
  model?: string;
  nonce: string;
  nonce_source?: string;
  nvidia_payload: NvidiaPayload;
  request_nonce: string;
  server_verification?: ServerVerification;
  signing_address: string;
  signing_algo?: string;
  signing_key?: string;
  signing_public_key: string;
  tee_hardware: string;
  tee_provider: string;
  upstream_model?: string;
  verified?: boolean;
  [key: string]: unknown;
};

export type NormalizationError = {
  message: string;
  path: string;
};

export type VerificationSummary = {
  badge: string;
  consistencyFailures: number;
  cryptographicStatus: CryptographicVerificationStatus;
  description: string;
  evidenceStatus: {
    intel: EvidenceVerificationStatus;
    nvidia: EvidenceVerificationStatus;
  };
  engineLabel: string;
  failedChecks: number;
  headline: string;
  infoChecks: number;
  intelRevocationCoverage: "not-run" | "complete" | "limited";
  mode: VerificationMode;
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
  normalizedReport?: NormalizedAttestationReport;
  parseErrors?: NormalizationError[];
  state: "idle" | "loaded" | "error";
  summary?: ReportSummary;
  verification: VerificationSummary;
};
