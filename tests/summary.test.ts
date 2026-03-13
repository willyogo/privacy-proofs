import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseReportSource } from "../src/lib/normalize";
import { sha256Hex } from "../src/lib/crypto";
import {
  INTEL_TDX_QE_IDENTITY,
  INTEL_TDX_TCB_INFO,
  INTEL_TDX_TCB_SIGN_CHAIN,
} from "./fixtures/intelVendor";
import { replaySyntheticRtmrs, withSyntheticDigests } from "./fixtures/eventLog";

const mocks = vi.hoisted(() => ({
  completeIntelOnlineVerification: vi.fn(),
  completeNvidiaOnlineVerification: vi.fn(),
  evaluateQeIdentity: vi.fn(),
  evaluateTcbInfo: vi.fn(),
  isCollateralCurrent: vi.fn(),
  parseIntelPckExtensions: vi.fn(),
  parseNvidiaEvidence: vi.fn(),
  validateCertificateChain: vi.fn(),
  verifyEcdsaSignature: vi.fn(),
  verifyIntelCollateralSignature: vi.fn(),
  verifyNvidiaEvidenceSignature: vi.fn(),
}));

vi.mock("../src/lib/certificates", () => ({
  validateCertificateChain: mocks.validateCertificateChain,
}));

vi.mock("../src/lib/crypto", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/crypto")>(
    "../src/lib/crypto",
  );

  return {
    ...actual,
    verifyEcdsaSignature: mocks.verifyEcdsaSignature,
  };
});

vi.mock("../src/lib/intel", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/intel")>(
    "../src/lib/intel",
  );

  return {
    ...actual,
    evaluateQeIdentity: mocks.evaluateQeIdentity,
    evaluateTcbInfo: mocks.evaluateTcbInfo,
    isCollateralCurrent: mocks.isCollateralCurrent,
    parseIntelPckExtensions: mocks.parseIntelPckExtensions,
    verifyIntelCollateralSignature: mocks.verifyIntelCollateralSignature,
  };
});

vi.mock("../src/lib/nvidia", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/nvidia")>(
    "../src/lib/nvidia",
  );

  return {
    ...actual,
    parseNvidiaEvidence: mocks.parseNvidiaEvidence,
    verifyNvidiaEvidenceSignature: mocks.verifyNvidiaEvidenceSignature,
  };
});

vi.mock("../src/lib/online-verification", () => ({
  completeIntelOnlineVerification: mocks.completeIntelOnlineVerification,
  completeNvidiaOnlineVerification: mocks.completeNvidiaOnlineVerification,
}));

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

type TestConfig = {
  appCertStatus: "pass" | "fail";
};

const testConfig: TestConfig = {
  appCertStatus: "pass",
};

describe("verdict construction", () => {
  let restoreImportKey: (() => void) | undefined;

  beforeEach(() => {
    testConfig.appCertStatus = "pass";

    mocks.validateCertificateChain.mockReset();
    mocks.verifyEcdsaSignature.mockReset();
    mocks.parseIntelPckExtensions.mockReset();
    mocks.verifyIntelCollateralSignature.mockReset();
    mocks.evaluateQeIdentity.mockReset();
    mocks.evaluateTcbInfo.mockReset();
    mocks.isCollateralCurrent.mockReset();
    mocks.completeIntelOnlineVerification.mockReset();
    mocks.completeNvidiaOnlineVerification.mockReset();
    mocks.parseNvidiaEvidence.mockReset();
    mocks.verifyNvidiaEvidenceSignature.mockReset();

    mocks.verifyEcdsaSignature.mockResolvedValue(true);
    mocks.parseIntelPckExtensions.mockReturnValue({
      cpuSvn: new Array(16).fill(1),
      fmspc: "ed742af8adf5",
      pceId: "8a67",
      pceSvn: 1,
    });
    mocks.verifyIntelCollateralSignature.mockResolvedValue(true);
    mocks.evaluateQeIdentity.mockReturnValue({
      acceptable: true,
      attributesMatch: true,
      isvprodidMatch: true,
      matchedLevel: undefined,
      miscselectMatch: true,
      mrsignerMatch: true,
      status: "UpToDate",
    });
    mocks.evaluateTcbInfo.mockReturnValue({
      acceptable: true,
      fmspcMatch: true,
      levelMatch: true,
      matchedLevel: undefined,
      pceIdMatch: true,
      status: "UpToDate",
      tdxModuleAttributesMatch: true,
      tdxModuleMrsignerMatch: true,
    });
    mocks.isCollateralCurrent.mockReturnValue(true);
    mocks.parseNvidiaEvidence.mockReturnValue({
      arch: "HOPPER",
      evidenceFwid: "aa".repeat(48),
      leafCertificateFwid: "aa".repeat(48),
      opaqueDataVersion: 1,
      requestNonce: BASE_NONCE,
      responseNonce: "bb".repeat(32),
      signature: new Uint8Array(96),
      signedBytes: new Uint8Array([1, 2, 3]),
    });
    mocks.verifyNvidiaEvidenceSignature.mockResolvedValue(true);
    mocks.completeIntelOnlineVerification.mockResolvedValue({
      checks: [],
      status: "verified",
    });
    mocks.completeNvidiaOnlineVerification.mockResolvedValue({
      checks: [],
      status: "verified",
    });
    mocks.validateCertificateChain.mockImplementation(async ({ bundleLabel, domain, jsonPath, severity = "blocking" }) => {
      const status =
        bundleLabel === "App certificate bundle" ? testConfig.appCertStatus : "pass";

      return {
        chain: [
          {
            publicKey: {
              rawData: new Uint8Array([1, 2, 3]),
            },
            rawData: new Uint8Array([4, 5, 6]),
          } as never,
        ],
        checks: [
          {
            description: `${bundleLabel} check`,
            domain: domain === "app" ? "app-cert" : domain === "intel" ? "tdx" : "nvidia",
            id: `${domain}-root-pin`,
            jsonPath,
            label: `Validate ${bundleLabel}`,
            severity,
            source: "local",
            status,
          },
        ],
      };
    });

    const importKeySpy = vi
      .spyOn(globalThis.crypto.subtle, "importKey")
      .mockResolvedValue({} as CryptoKey);
    restoreImportKey = () => importKeySpy.mockRestore();
  });

  afterEach(() => {
    restoreImportKey?.();
    restoreImportKey = undefined;
    vi.unstubAllGlobals();
  });

  it("returns partial when quote cryptography passes but Intel collateral is absent", async () => {
    const result = await parseReportSource(JSON.stringify(buildReport()), "fixture.json");

    expect(result.verification.status).toBe("partially-verified");
    expect(result.verification.evidenceStatus.intel).toBe("partial");
    expect(
      result.checks.find((check) => check.id === "intel-collateral-availability")?.status,
    ).toBe("info");
  });

  it("does not invalidate the report when the app certificate bundle is present but invalid", async () => {
    testConfig.appCertStatus = "fail";

    const result = await parseReportSource(
      JSON.stringify(buildReport({ appCert: "not-a-real-certificate" })),
      "fixture.json",
    );

    expect(result.verification.status).toBe("partially-verified");
    expect(
      result.checks.find((check) => check.id === "app-root-pin")?.severity,
    ).toBe("advisory");
  });

  it("fails conflicting duplicate security-critical event names", async () => {
    const result = await parseReportSource(
      JSON.stringify(
        buildReport({
          duplicateEvents: [
            {
              event: "compose-hash",
              event_payload: "11".repeat(32),
            },
          ],
        }),
      ),
      "fixture.json",
    );

    expect(result.verification.status).toBe("invalid");
    expect(
      result.checks.find((check) => check.id === "event-log-compose-hash")?.status,
    ).toBe("fail");
  });

  it("keeps NVIDIA arch mismatches advisory-only", async () => {
    const result = await parseReportSource(
      JSON.stringify(
        buildReport({
          entryArch: "BLACKWELL",
          payloadArch: "HOPPER",
        }),
      ),
      "fixture.json",
    );

    expect(result.verification.status).toBe("partially-verified");
    expect(
      result.checks.find((check) => check.id === "nvidia-evidence-arch-0")?.severity,
    ).toBe("advisory");
  });

  it("reaches verified only when full Intel collateral is present and accepted", async () => {
    const result = await parseReportSource(
      JSON.stringify(
        buildReport({
          intelQeIdentity: INTEL_TDX_QE_IDENTITY,
          intelSignedTcbInfo: INTEL_TDX_TCB_INFO,
          intelTcbSignChain: INTEL_TDX_TCB_SIGN_CHAIN,
        }),
      ),
      "fixture.json",
    );

    expect(result.verification.status).toBe("verified");
    expect(result.verification.evidenceStatus.intel).toBe("verified");
    expect(result.verification.badge).toBe("Locally verified");
  });

  it("reaches fully verified when online Intel and NVIDIA completion both succeed", async () => {
    const result = await parseReportSource(JSON.stringify(buildReport()), "fixture.json", {
      mode: "online",
      online: {
        nvidiaApiKey: "fixture-api-key",
      },
    });

    expect(mocks.completeIntelOnlineVerification).toHaveBeenCalledTimes(1);
    expect(mocks.completeNvidiaOnlineVerification).toHaveBeenCalledTimes(1);
    expect(result.verification.status).toBe("verified");
    expect(result.verification.badge).toBe("Fully verified");
    expect(result.verification.mode).toBe("online");
    expect(result.verification.evidenceStatus).toEqual({
      intel: "verified",
      nvidia: "verified",
    });
  });

  it("stays partial when NVIDIA online completion cannot finish", async () => {
    mocks.completeNvidiaOnlineVerification.mockResolvedValue({
      checks: [
        {
          description: "NRAS authentication was unavailable.",
          domain: "nvidia",
          id: "nvidia-online-auth",
          jsonPath: "$.nvidia_payload",
          label: "Authorize NVIDIA NRAS request",
          severity: "advisory",
          source: "online",
          status: "fail",
        },
      ],
      status: "partial",
    });

    const result = await parseReportSource(JSON.stringify(buildReport()), "fixture.json", {
      mode: "online",
      online: {
        nvidiaApiKey: "fixture-api-key",
      },
    });

    expect(result.verification.status).toBe("partially-verified");
    expect(result.verification.headline).toBe("Online verification incomplete");
    expect(result.verification.evidenceStatus).toEqual({
      intel: "verified",
      nvidia: "partial",
    });
    expect(
      result.checks.find((check) => check.id === "nvidia-online-auth")?.source,
    ).toBe("online");
  });

  it("excludes embedded provenance passes from the headline check count", async () => {
    const result = await parseReportSource(
      JSON.stringify(
        buildReport({
          serverVerification: {
            nvidia: { valid: true },
            signingAddressBinding: {
              reportDataAddress: BASE_SIGNING_ADDRESS,
            },
            tdx: { valid: true },
            verifiedAt: "2026-03-11T15:42:20.617Z",
          },
        }),
      ),
      "fixture.json",
    );

    const nonEmbeddedSupportedChecks = result.checks.filter(
      (check) => check.source !== "embedded" && check.status !== "info",
    ).length;
    const embeddedPassingChecks = result.checks.filter(
      (check) => check.source === "embedded" && check.status === "pass",
    ).length;

    expect(embeddedPassingChecks).toBeGreaterThan(0);
    expect(result.verification.supportedChecks).toBe(nonEmbeddedSupportedChecks);
  });
});

function buildReport({
  appCert,
  duplicateEvents = [],
  entryArch = "HOPPER",
  intelQeIdentity,
  intelSignedTcbInfo,
  intelTcbSignChain,
  payloadArch = entryArch,
  serverVerification,
}: {
  appCert?: string;
  duplicateEvents?: Array<{ event: string; event_payload: string }>;
  entryArch?: string;
  intelQeIdentity?: unknown;
  intelSignedTcbInfo?: unknown;
  intelTcbSignChain?: string;
  payloadArch?: string;
  serverVerification?: Record<string, unknown>;
} = {}) {
  const composeHash =
    "39eaa3f466bb30f10e9d2be1b103b2d97d452f4d3dd15fcc9c6fb1f1023bfdba";
  const baseEventLog = withSyntheticDigests([
    {
      event: "app-id",
      event_payload: "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b",
      event_type: 134217729,
      imr: 3,
    },
    {
      event: "compose-hash",
      event_payload: composeHash,
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
  const eventLog = withSyntheticDigests([
    ...baseEventLog,
    ...duplicateEvents.map((entry, index) => ({
      event: entry.event,
      event_payload: entry.event_payload,
      event_type: 134217729,
      imr: 3,
      index,
    })),
  ]);
  const rtmrs = replaySyntheticRtmrs(eventLog);

  const reportDataHex =
    `${BASE_SIGNING_ADDRESS.slice(2).toLowerCase()}${"0".repeat(24)}${BASE_NONCE}`;

  return {
    event_log: eventLog,
    info: {
      ...(appCert ? { app_cert: appCert } : {}),
      app_id: "2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b",
      app_name: "fixture",
      compose_hash: composeHash,
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
    ...(intelQeIdentity ? { intel_qe_identity: intelQeIdentity } : {}),
    ...(intelSignedTcbInfo ? { intel_signed_tcb_info: intelSignedTcbInfo } : {}),
    ...(intelTcbSignChain ? { intel_tcb_sign_chain: intelTcbSignChain } : {}),
    intel_quote: buildQuoteHex({ composeHash, reportDataHex, rtmrs }),
    nonce: BASE_NONCE,
    nvidia_payload: {
      arch: payloadArch,
      evidence_list: [
        {
          arch: entryArch,
          certificate: btoa("fixture-certificate-chain"),
          evidence: btoa("fixture-evidence"),
        },
      ],
      nonce: BASE_NONCE,
    },
    request_nonce: BASE_NONCE,
    signing_address: BASE_SIGNING_ADDRESS,
    signing_key: BASE_SIGNING_PUBLIC_KEY,
    signing_public_key: BASE_SIGNING_PUBLIC_KEY,
    tee_hardware: "intel-tdx",
    tee_provider: "near-ai",
    ...(serverVerification ? { server_verification: serverVerification } : {}),
    verified: true,
  };
}

function buildQuoteHex({
  composeHash,
  reportDataHex,
  rtmrs,
}: {
  composeHash: string;
  reportDataHex: string;
  rtmrs: Record<"rtmr0" | "rtmr1" | "rtmr2" | "rtmr3", string>;
}) {
  const certificationDataBytes = new TextEncoder().encode(
    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
  );
  const outerCertificationDataSize = 384 + 64 + 2 + 6 + certificationDataBytes.length;
  const authDataLength = 64 + 64 + 6 + outerCertificationDataSize;
  const quote = new Uint8Array(636 + authDataLength);
  const view = new DataView(quote.buffer);
  const qeReportDataHex = `${sha256Hex(new Uint8Array(64))}${"0".repeat(64)}`;

  view.setUint16(0, 4, true);
  view.setUint32(632, authDataLength, true);
  quote.set(hexToBytes(`01${composeHash}${"00".repeat(15)}`), 48 + 184);
  quote.set(hexToBytes(reportDataHex), 48 + 520);
  quote.set(hexToBytes(rtmrs.rtmr0), 48 + 328);
  quote.set(hexToBytes(rtmrs.rtmr1), 48 + 376);
  quote.set(hexToBytes(rtmrs.rtmr2), 48 + 424);
  quote.set(hexToBytes(rtmrs.rtmr3), 48 + 472);

  let offset = 636;
  offset += 64; // quote signature
  offset += 64; // attestation public key
  view.setUint16(offset, 6, true);
  view.setUint32(offset + 2, outerCertificationDataSize, true);
  offset += 6;
  quote.set(hexToBytes(qeReportDataHex), offset + 320);
  offset += 384; // qe report
  offset += 64; // qe report signature
  view.setUint16(offset, 0, true);
  offset += 2;
  view.setUint16(offset, 5, true);
  view.setUint32(offset + 2, certificationDataBytes.length, true);
  offset += 6;
  quote.set(certificationDataBytes, offset);

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
