import { afterEach, describe, expect, it, vi } from "vitest";
import { parseReportSource } from "../src/lib/normalize";
import { replaySyntheticRtmrs, withSyntheticDigests } from "./fixtures/eventLog";

const BASE_SIGNING_PUBLIC_KEY =
  "049eb9f800a6d38ac3c30526d812ba9aa49fc0e5f14d7f67ae17e56aa4d9a43f1c274540b74dab8405b5fef5dfbe3431bf5ad7efcf7279008b460c4930bb8f6606";
const BASE_SIGNING_ADDRESS = "0x4B19f7f8Fd7757AAb29a8990bb11f6aA3572C9B1";
const BASE_NONCE =
  "d8786ff291199a0c41654bd828a67c996331a74b457b7d6831e8cef938222be3";
const KEY_PROVIDER_INFO = JSON.stringify({
  id: "kms-key",
  name: "kms",
});
const KEY_PROVIDER_INFO_HEX = Array.from(new TextEncoder().encode(KEY_PROVIDER_INFO))
  .map((byte) => byte.toString(16).padStart(2, "0"))
  .join("");

describe("parseReportSource", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("returns an error for invalid JSON", async () => {
    const result = await parseReportSource("{broken");

    expect(result.state).toBe("error");
    expect(result.checks[0]?.status).toBe("fail");
    expect(result.verification.status).toBe("invalid");
  });

  it("flags schema failures for missing required fields", async () => {
    const result = await parseReportSource(
      JSON.stringify({
        info: {},
      }),
    );

    expect(result.state).toBe("error");
    expect(result.checks.some((check) => check.id.startsWith("schema-"))).toBe(true);
  });

  it("fails verification for compressed signing public keys", async () => {
    const report = buildBaseReport({
      signing_public_key: `02${"11".repeat(32)}`,
      signing_key: `02${"11".repeat(32)}`,
    });

    const result = await parseReportSource(JSON.stringify(report), "compressed.json");

    expect(result.verification.status).toBe("invalid");
    expect(
      result.checks.find((check) => check.id === "signing-address-binding")?.status,
    ).toBe("fail");
  });

  it("treats a missing optional signing_key field as informational", async () => {
    const report = buildBaseReport({
      signing_key: undefined,
    });

    const result = await parseReportSource(JSON.stringify(report), "missing-signing-key.json");

    expect(
      result.checks.find((check) => check.id === "signing-key-consistency")?.status,
    ).toBe("info");
  });

  it("treats unsupported TDX quote versions as blocking failures", async () => {
    const report = buildBaseReport({
      intel_quote: buildQuoteHex({ version: 5 }),
    });

    const result = await parseReportSource(JSON.stringify(report), "unsupported.json");

    expect(result.verification.status).toBe("invalid");
    expect(
      result.checks.find((check) => check.id === "tdx-quote-shape")?.status,
    ).toBe("fail");
  });

  it("accepts MRCONFIGID layouts that prefix the compose hash with 0x01", async () => {
    const composeHash =
      "39eaa3f466bb30f10e9d2be1b103b2d97d452f4d3dd15fcc9c6fb1f1023bfdba";
    const report = buildBaseReport({
      intel_quote: buildQuoteHex({
        mrConfigIdHex: `01${composeHash}${"00".repeat(15)}`,
        version: 4,
      }),
    });

    const result = await parseReportSource(JSON.stringify(report), "mrconfigid-prefix.json");

    expect(
      result.checks.find((check) => check.id === "tdx-compose-hash")?.status,
    ).toBe("pass");
  });

  it("never invokes fetch while verifying a raw report", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    await parseReportSource(JSON.stringify(buildBaseReport()), "fixture.json");

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("fails when the event log replay does not match the quote RTMRs", async () => {
    const report = buildBaseReport();
    report.event_log = report.event_log.map((entry, index) => {
      if (index !== 0) {
        return entry;
      }

      return {
        ...entry,
        digest: "ff".repeat(48),
      };
    });

    const result = await parseReportSource(JSON.stringify(report), "tampered-event-log.json");

    expect(result.verification.status).toBe("invalid");
    expect(
      result.checks.find((check) => check.id === "event-log-rtmr3")?.status,
    ).toBe("fail");
  });

  it("uses the local verifier time rather than embedded verifiedAt in offline summaries", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-13T17:45:00.000Z"));

    const result = await parseReportSource(JSON.stringify(buildBaseReport()), "fixture.json");

    expect(result.summary?.verifiedAt).toBe("2026-03-13T17:45:00.000Z");
  });
});

function buildBaseReport(overrides: Record<string, unknown> = {}) {
  const eventLog = withSyntheticDigests([
    {
      event: "app-id",
      event_payload: "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b",
      event_type: 134217729,
      imr: 3,
    },
    {
      event: "compose-hash",
      event_payload: "39eaa3f466bb30f10e9d2be1b103b2d97d452f4d3dd15fcc9c6fb1f1023bfdba",
      event_type: 134217729,
      imr: 3,
    },
    {
      event: "instance-id",
      event_payload: "d91376e26c0be974730f66ca0cc9dadb2f0e3a85",
      event_type: 134217729,
      imr: 3,
    },
    {
      event: "os-image-hash",
      event_payload: "9b69bb1698bacbb6985409a2c272bcb892e09cdcea63d5399c6768b67d3ff677",
      event_type: 134217729,
      imr: 3,
    },
    {
      event: "key-provider",
      event_payload: KEY_PROVIDER_INFO_HEX,
      event_type: 134217729,
      imr: 3,
    },
  ]);
  const rtmrs = replaySyntheticRtmrs(eventLog);

  return {
    event_log: eventLog,
    info: {
      app_cert: "",
      app_id: "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b",
      app_name: "fixture",
      compose_hash: "39eaa3f466bb30f10e9d2be1b103b2d97d452f4d3dd15fcc9c6fb1f1023bfdba",
      instance_id: "d91376e26c0be974730f66ca0cc9dadb2f0e3a85",
      key_provider_info: KEY_PROVIDER_INFO,
      tcb_info: {
        event_log: eventLog,
        mrtd: "00".repeat(48),
        os_image_hash: "9b69bb1698bacbb6985409a2c272bcb892e09cdcea63d5399c6768b67d3ff677",
        rtmr0: rtmrs.rtmr0,
        rtmr1: rtmrs.rtmr1,
        rtmr2: rtmrs.rtmr2,
        rtmr3: rtmrs.rtmr3,
      },
    },
    intel_quote: buildQuoteHex({ rtmrs, version: 4 }),
    nvidia_payload: JSON.stringify({
      arch: "HOPPER",
      evidence_list: [
        {
          arch: "HOPPER",
          certificate: btoa("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
          evidence: btoa("fixture-evidence"),
        },
      ],
      nonce: BASE_NONCE,
    }),
    nonce: BASE_NONCE,
    request_nonce: BASE_NONCE,
    server_verification: {
      nvidia: { valid: true },
      tdx: { valid: true },
      verifiedAt: "2026-03-11T15:42:20.617Z",
    },
    signing_address: BASE_SIGNING_ADDRESS,
    signing_key: BASE_SIGNING_PUBLIC_KEY,
    signing_public_key: BASE_SIGNING_PUBLIC_KEY,
    tee_hardware: "intel-tdx",
    tee_provider: "near-ai",
    verified: true,
    ...overrides,
  };
}

function buildQuoteHex({
  mrConfigIdHex,
  rtmrs,
  version,
}: {
  mrConfigIdHex?: string;
  rtmrs?: Record<"rtmr0" | "rtmr1" | "rtmr2" | "rtmr3", string>;
  version: number;
}) {
  const authDataLength = 64 + 64 + 6 + 384 + 64 + 2 + 6;
  const quote = new Uint8Array(636 + authDataLength);
  const view = new DataView(quote.buffer);
  view.setUint16(0, version, true);
  view.setUint32(632, authDataLength, true);

  if (mrConfigIdHex) {
    const mrConfigIdBytes = hexToBytes(mrConfigIdHex);
    quote.set(mrConfigIdBytes, 48 + 184);
  }

  if (rtmrs) {
    quote.set(hexToBytes(rtmrs.rtmr0), 48 + 328);
    quote.set(hexToBytes(rtmrs.rtmr1), 48 + 376);
    quote.set(hexToBytes(rtmrs.rtmr2), 48 + 424);
    quote.set(hexToBytes(rtmrs.rtmr3), 48 + 472);
  }

  let offset = 636;
  offset += 64; // quote signature
  offset += 64; // attestation public key
  view.setUint16(offset, 6, true);
  view.setUint32(offset + 2, 456, true);
  offset += 6;
  offset += 384; // qe report
  offset += 64; // qe report signature
  view.setUint16(offset, 0, true);
  offset += 2;
  view.setUint16(offset, 5, true);
  view.setUint32(offset + 2, 0, true);

  return Array.from(quote)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(value: string): Uint8Array {
  const normalized = value.replace(/^0x/i, "");
  const bytes = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }

  return bytes;
}
