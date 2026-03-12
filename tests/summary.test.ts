import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const verifyNormalizedReport = vi.fn();

vi.mock("../src/lib/verifier", () => ({
  verifyNormalizedReport,
}));

describe("verdict construction", () => {
  beforeEach(() => {
    verifyNormalizedReport.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("does not upgrade to verified when embedded claims are present but crypto is partial", async () => {
    verifyNormalizedReport.mockResolvedValue({
      checks: [
        {
          description: "embedded claims were present",
          domain: "provenance",
          id: "embedded-verification-claims",
          jsonPath: "$.server_verification",
          label: "Inspect embedded verification claims",
          severity: "advisory",
          source: "embedded",
          status: "pass",
        },
      ],
      cryptographicStatus: "partial",
      derivedSigningAddress: "0x4B19f7f8Fd7757AAb29a8990bb11f6aA3572C9B1",
      mode: "offline",
      evidenceStatus: {
        intel: "partial",
        nvidia: "verified",
      },
      quoteReportData: undefined,
      verifiedAt: "2026-03-11T15:42:20.617Z",
    });

    const { parseReportSource } = await import("../src/lib/normalize");
    const result = await parseReportSource(
      JSON.stringify(buildSchemaValidReport()),
      "fixture.json",
    );

    expect(result.verification.status).toBe("partially-verified");
    expect(result.verification.cryptographicStatus).toBe("partial");
  });
});

function buildSchemaValidReport() {
  return {
    event_log: [],
    info: {},
    intel_quote: "00",
    nonce: "00",
    nvidia_payload: JSON.stringify({
      evidence_list: [],
    }),
    request_nonce: "00",
    signing_address: "0x0000000000000000000000000000000000000000",
    signing_public_key: "04" + "00".repeat(64),
    tee_hardware: "intel-tdx",
    tee_provider: "near-ai",
    verified: true,
  };
}
