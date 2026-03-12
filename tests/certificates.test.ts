import { describe, expect, it } from "vitest";
import {
  splitPemBundle,
  validateCertificateChain,
} from "../src/lib/certificates";
import {
  INTEL_TDX_TCB_SIGN_CHAIN,
  NVIDIA_HOPPER_EVIDENCE,
} from "./fixtures/vendorSamples";

function decodeBase64Utf8(value: string): string {
  return new TextDecoder().decode(
    Uint8Array.from(atob(value), (char) => char.charCodeAt(0)),
  );
}

describe("certificate anchoring", () => {
  it("anchors an Intel chain to the local pinned root when the root is omitted from the bundle", async () => {
    const [, processorCa] = splitPemBundle(INTEL_TDX_TCB_SIGN_CHAIN);
    expect(processorCa).toBeDefined();

    const result = await validateCertificateChain({
      bundle: processorCa!,
      bundleLabel: "Intel TCB signing chain",
      domain: "intel",
      jsonPath: "$.intel.tcbSignChain",
    });

    expect(
      result.checks.some(
        (check) => check.severity === "blocking" && check.status === "fail",
      ),
    ).toBe(false);
    expect(result.chain?.at(-1)?.subject).toContain("Intel SGX Root CA");
  });

  it("rejects an unrelated pinned Intel root appended to a foreign chain", async () => {
    const [intelRoot] = splitPemBundle(INTEL_TDX_TCB_SIGN_CHAIN);
    const nvidiaBundle = decodeBase64Utf8(NVIDIA_HOPPER_EVIDENCE.certificate);

    const result = await validateCertificateChain({
      bundle: `${nvidiaBundle}\n${intelRoot ?? ""}`,
      bundleLabel: "Mixed chain",
      domain: "intel",
      jsonPath: "$.mixed",
    });

    expect(result.checks.find((check) => check.id === "intel-root-pin")?.status).toBe("fail");
  });
});
