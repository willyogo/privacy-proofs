import { describe, expect, it } from "vitest";
import { validateCertificateChain } from "../src/lib/certificates";
import {
  parseNvidiaEvidence,
  verifyNvidiaEvidenceSignature,
} from "../src/lib/nvidia";
import { NVIDIA_HOPPER_EVIDENCE } from "./fixtures/vendorSamples";

function decodeBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

describe("NVIDIA evidence verification", () => {
  it("verifies the official Hopper evidence sample", async () => {
    const chainResult = await validateCertificateChain({
      bundle: new TextDecoder().decode(decodeBase64(NVIDIA_HOPPER_EVIDENCE.certificate)),
      bundleLabel: "NVIDIA certificate chain",
      domain: "nvidia",
      jsonPath: "$.nvidia_payload.evidence_list[0].certificate",
    });

    expect(
      chainResult.checks.some(
        (check) => check.severity === "blocking" && check.status === "fail",
      ),
    ).toBe(false);

    const evidence = decodeBase64(NVIDIA_HOPPER_EVIDENCE.evidence);
    const parsed = parseNvidiaEvidence({
      arch: NVIDIA_HOPPER_EVIDENCE.arch,
      evidence,
      leafCertificate: chainResult.chain![0]!,
    });

    expect(parsed).toBeDefined();
    expect(parsed?.requestNonce).toBe(NVIDIA_HOPPER_EVIDENCE.nonce);
    expect(parsed?.evidenceFwid).toBeDefined();
    expect(parsed?.leafCertificateFwid).toBeDefined();
    expect(parsed?.evidenceFwid).toBe(parsed?.leafCertificateFwid);

    const signatureValid = await verifyNvidiaEvidenceSignature({
      leafCertificate: chainResult.chain![0]!,
      signature: parsed!.signature,
      signedBytes: parsed!.signedBytes,
    });

    expect(signatureValid).toBe(true);
  });

  it("rejects tampered NVIDIA evidence signatures", async () => {
    const chainResult = await validateCertificateChain({
      bundle: new TextDecoder().decode(decodeBase64(NVIDIA_HOPPER_EVIDENCE.certificate)),
      bundleLabel: "NVIDIA certificate chain",
      domain: "nvidia",
      jsonPath: "$.nvidia_payload.evidence_list[0].certificate",
    });

    const evidence = decodeBase64(NVIDIA_HOPPER_EVIDENCE.evidence);
    evidence[evidence.length - 1] ^= 0xff;

    const parsed = parseNvidiaEvidence({
      arch: NVIDIA_HOPPER_EVIDENCE.arch,
      evidence,
      leafCertificate: chainResult.chain![0]!,
    });

    const signatureValid = await verifyNvidiaEvidenceSignature({
      leafCertificate: chainResult.chain![0]!,
      signature: parsed!.signature,
      signedBytes: parsed!.signedBytes,
    });

    expect(signatureValid).toBe(false);
  });

  it("fails to parse malformed NVIDIA evidence blobs", async () => {
    const chainResult = await validateCertificateChain({
      bundle: new TextDecoder().decode(decodeBase64(NVIDIA_HOPPER_EVIDENCE.certificate)),
      bundleLabel: "NVIDIA certificate chain",
      domain: "nvidia",
      jsonPath: "$.nvidia_payload.evidence_list[0].certificate",
    });

    const malformedEvidence = decodeBase64(NVIDIA_HOPPER_EVIDENCE.evidence).slice(0, 40);
    const parsed = parseNvidiaEvidence({
      arch: NVIDIA_HOPPER_EVIDENCE.arch,
      evidence: malformedEvidence,
      leafCertificate: chainResult.chain![0]!,
    });

    expect(parsed).toBeUndefined();
  });
});
