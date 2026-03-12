import { z } from "zod";
import type {
  EventLogEntry,
  InfoBlock,
  IntelSignedQeIdentity,
  IntelSignedTcbInfo,
  NormalizationError,
  NormalizedAttestationReport,
  NvidiaPayload,
  ServerVerification,
  TcbInfo,
} from "./types";

const eventLogEntrySchema = z
  .object({
    digest: z.string().optional(),
    event: z.string().optional(),
    event_payload: z.string().optional(),
    event_type: z.number().optional(),
    imr: z.number().optional(),
  })
  .passthrough();

const tcbInfoSchema = z
  .object({
    app_compose: z.string().optional(),
    compose_hash: z.string().optional(),
    device_id: z.string().optional(),
    event_log: z.array(eventLogEntrySchema).optional(),
    mr_aggregated: z.string().optional(),
    mrtd: z.string().optional(),
    os_image_hash: z.string().optional(),
    rtmr0: z.string().optional(),
    rtmr1: z.string().optional(),
    rtmr2: z.string().optional(),
    rtmr3: z.string().optional(),
  })
  .passthrough();

const infoSchema = z
  .object({
    app_cert: z.string().optional(),
    app_id: z.string().optional(),
    app_name: z.string().optional(),
    compose_hash: z.string().optional(),
    device_id: z.string().optional(),
    instance_id: z.string().optional(),
    key_provider_info: z.union([z.string(), z.record(z.string(), z.unknown())]).optional(),
    mr_aggregated: z.string().optional(),
    os_image_hash: z.string().optional(),
    tcb_info: tcbInfoSchema.optional(),
    vm_config: z.union([z.string(), z.record(z.string(), z.unknown())]).optional(),
  })
  .passthrough();

const nvidiaEvidenceEntrySchema = z
  .object({
    arch: z.string().optional(),
    certificate: z.string(),
    evidence: z.string(),
    nonce: z.string().optional(),
  })
  .passthrough();

const nvidiaPayloadObjectSchema = z
  .object({
    arch: z.string().optional(),
    evidence_list: z.array(nvidiaEvidenceEntrySchema).default([]),
    nonce: z.string().optional(),
  })
  .passthrough();

const serverVerificationSchema = z
  .object({
    nonceBinding: z.record(z.string(), z.unknown()).optional(),
    nvidia: z.record(z.string(), z.unknown()).optional(),
    nvidiaNonceBinding: z.record(z.string(), z.unknown()).optional(),
    signingAddressBinding: z.record(z.string(), z.unknown()).optional(),
    tdx: z.record(z.string(), z.unknown()).optional(),
    verificationDurationMs: z.number().optional(),
    verifiedAt: z.string().optional(),
  })
  .passthrough();

const intelQeIdentityLevelSchema = z.object({
  advisoryIDs: z.array(z.string()).optional(),
  tcb: z.object({
    isvsvn: z.number(),
  }),
  tcbDate: z.string(),
  tcbStatus: z.string(),
});

const intelSignedQeIdentityObjectSchema = z.object({
  enclaveIdentity: z.object({
    attributes: z.string(),
    attributesMask: z.string(),
    id: z.string(),
    isvprodid: z.number(),
    issueDate: z.string(),
    miscselect: z.string(),
    miscselectMask: z.string(),
    mrsigner: z.string(),
    nextUpdate: z.string(),
    tcbEvaluationDataNumber: z.number(),
    tcbLevels: z.array(intelQeIdentityLevelSchema),
    version: z.number(),
  }),
  signature: z.string(),
});

const intelTcbComponentSchema = z
  .object({
    category: z.string().optional(),
    svn: z.number(),
    type: z.string().optional(),
  })
  .passthrough();

const intelTcbLevelSchema = z.object({
  advisoryIDs: z.array(z.string()).optional(),
  tcb: z.object({
    pcesvn: z.number(),
    sgxtcbcomponents: z.array(intelTcbComponentSchema).length(16),
    tdxtcbcomponents: z.array(intelTcbComponentSchema).length(16).optional(),
  }),
  tcbDate: z.string(),
  tcbStatus: z.string(),
});

const intelSignedTcbInfoObjectSchema = z.object({
  tcbInfo: z.object({
    fmspc: z.string(),
    id: z.string(),
    issueDate: z.string(),
    nextUpdate: z.string(),
    pceId: z.string(),
    tcbEvaluationDataNumber: z.number(),
    tcbLevels: z.array(intelTcbLevelSchema),
    tcbType: z.number().optional(),
    tdxModule: z
      .object({
        attributes: z.string(),
        attributesMask: z.string(),
        mrsigner: z.string(),
      })
      .optional(),
    version: z.number(),
  }),
  signature: z.string(),
});

const intelSignedQeIdentitySchema = z.union([
  intelSignedQeIdentityObjectSchema,
  z.string().transform((value, ctx) => {
    try {
      const parsed = JSON.parse(value);
      return intelSignedQeIdentityObjectSchema.parse(parsed);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          error instanceof Error
            ? `The Intel QE identity could not be decoded as JSON: ${error.message}`
            : "The Intel QE identity could not be decoded as JSON.",
      });
      return z.NEVER;
    }
  }),
]);

const intelSignedTcbInfoSchema = z.union([
  intelSignedTcbInfoObjectSchema,
  z.string().transform((value, ctx) => {
    try {
      const parsed = JSON.parse(value);
      return intelSignedTcbInfoObjectSchema.parse(parsed);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          error instanceof Error
            ? `The Intel TCB info could not be decoded as JSON: ${error.message}`
            : "The Intel TCB info could not be decoded as JSON.",
      });
      return z.NEVER;
    }
  }),
]);

const nvidiaPayloadSchema = z.union([
  nvidiaPayloadObjectSchema,
  z.string().transform((value, ctx) => {
    try {
      const parsed = JSON.parse(value);
      return nvidiaPayloadObjectSchema.parse(parsed);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          error instanceof Error
            ? `The NVIDIA payload could not be decoded as JSON: ${error.message}`
            : "The NVIDIA payload could not be decoded as JSON.",
      });
      return z.NEVER;
    }
  }),
]);

export const REQUIRED_TOP_LEVEL_FIELDS = [
  "event_log",
  "info",
  "intel_quote",
  "nvidia_payload",
  "request_nonce",
  "signing_address",
  "signing_public_key",
  "nonce",
  "tee_hardware",
  "tee_provider",
] as const;

export const normalizedAttestationReportSchema = z
  .object({
    event_log: z.array(eventLogEntrySchema),
    info: infoSchema,
    intel_quote: z.string(),
    model: z.string().optional(),
    nonce: z.string(),
    nonce_source: z.string().optional(),
    nvidia_payload: nvidiaPayloadSchema,
    request_nonce: z.string(),
    server_verification: serverVerificationSchema.optional(),
    signing_address: z.string(),
    signing_algo: z.string().optional(),
    signing_key: z.string().optional(),
    signing_public_key: z.string(),
    tee_hardware: z.string(),
    tee_provider: z.string(),
    upstream_model: z.string().optional(),
    verified: z.boolean().optional(),
  })
  .passthrough()
  .transform((report) => ({
    ...report,
    nvidia_payload:
      typeof report.nvidia_payload === "string"
        ? nvidiaPayloadObjectSchema.parse(JSON.parse(report.nvidia_payload))
        : report.nvidia_payload,
  }));

export function parseAttestationReport(
  value: unknown,
):
  | { ok: true; value: NormalizedAttestationReport }
  | { errors: NormalizationError[]; ok: false } {
  const result = normalizedAttestationReportSchema.safeParse(value);

  if (result.success) {
    return {
      ok: true,
      value: result.data as NormalizedAttestationReport,
    };
  }

  return {
    ok: false,
    errors: mapZodIssues(result.error.issues),
  };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asEventLogEntry(value: unknown): EventLogEntry | undefined {
  return eventLogEntrySchema.safeParse(value).success
    ? (value as EventLogEntry)
    : undefined;
}

export function asInfoBlock(value: unknown): InfoBlock | undefined {
  return infoSchema.safeParse(value).success ? (value as InfoBlock) : undefined;
}

export function asNvidiaPayload(value: unknown): NvidiaPayload | undefined {
  return nvidiaPayloadObjectSchema.safeParse(value).success
    ? (value as NvidiaPayload)
    : undefined;
}

export function asServerVerification(
  value: unknown,
): ServerVerification | undefined {
  return serverVerificationSchema.safeParse(value).success
    ? (value as ServerVerification)
    : undefined;
}

export function asTcbInfo(value: unknown): TcbInfo | undefined {
  return tcbInfoSchema.safeParse(value).success ? (value as TcbInfo) : undefined;
}

export function asIntelSignedQeIdentity(
  value: unknown,
): IntelSignedQeIdentity | undefined {
  const result = intelSignedQeIdentitySchema.safeParse(value);
  return result.success ? result.data : undefined;
}

export function asIntelSignedTcbInfo(
  value: unknown,
): IntelSignedTcbInfo | undefined {
  const result = intelSignedTcbInfoSchema.safeParse(value);
  return result.success ? result.data : undefined;
}

function mapZodIssues(issues: z.ZodIssue[]): NormalizationError[] {
  return issues.map((issue) => ({
    message: issue.message,
    path:
      issue.path.length > 0
        ? `$.${issue.path
            .map((segment) =>
              typeof segment === "number" ? `[${segment}]` : String(segment),
            )
            .join(".")
            .replace(/\.\[/g, "[")}`
        : "$",
  }));
}
