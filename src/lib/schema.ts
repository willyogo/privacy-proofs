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

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
