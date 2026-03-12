import { describe, expect, it } from "vitest";
import { validateCertificateChain } from "../src/lib/certificates";
import {
  evaluateQeIdentity,
  evaluateTcbInfo,
  extractIntelSignedBodyText,
  isCollateralCurrent,
  parseIntelPckExtensions,
  parseQeReport,
  verifyIntelCollateralSignature,
} from "../src/lib/intel";
import { decodeTdxQuote } from "../src/lib/verifier";
import {
  INTEL_TDX_QE_IDENTITY,
  INTEL_TDX_QUOTE_HEX,
  INTEL_TDX_TCB_INFO,
  INTEL_TDX_TCB_SIGN_CHAIN,
} from "./fixtures/intelVendor";

describe("Intel collateral verification", () => {
  it("verifies the official TDX sample signatures and detects the QE identity mismatch", async () => {
    const quote = decodeTdxQuote(INTEL_TDX_QUOTE_HEX);
    expect(quote).toBeDefined();
    expect(quote?.version).toBe(4);

    const pckChain = await validateCertificateChain({
      bundle: quote!.certificationData!,
      bundleLabel: "Intel PCK certificate chain",
      domain: "intel",
      jsonPath: "$.intel_quote",
    });
    expect(pckChain.chain?.[0]).toBeDefined();
    expect(
      pckChain.checks.some(
        (check) => check.severity === "blocking" && check.status === "fail",
      ),
    ).toBe(false);

    const tcbSigningChain = await validateCertificateChain({
      bundle: INTEL_TDX_TCB_SIGN_CHAIN,
      bundleLabel: "Intel TCB signing chain",
      domain: "intel",
      jsonPath: "$.intel.tcbSignChain",
    });
    expect(
      tcbSigningChain.checks.some(
        (check) => check.severity === "blocking" && check.status === "fail",
      ),
    ).toBe(false);

    const qeIdentitySignatureValid = await verifyIntelCollateralSignature({
      body: INTEL_TDX_QE_IDENTITY.enclaveIdentity,
      chain: tcbSigningChain.chain!,
      signatureHex: INTEL_TDX_QE_IDENTITY.signature,
    });
    expect(qeIdentitySignatureValid).toBe(true);

    const tcbInfoSignatureValid = await verifyIntelCollateralSignature({
      body: INTEL_TDX_TCB_INFO.tcbInfo,
      chain: tcbSigningChain.chain!,
      signatureHex: INTEL_TDX_TCB_INFO.signature,
    });
    expect(tcbInfoSignatureValid).toBe(true);

    const qeReport = parseQeReport(quote!.qeReport!);
    expect(qeReport).toBeDefined();

    const qeIdentityEvaluation = evaluateQeIdentity({
      qeIdentity: INTEL_TDX_QE_IDENTITY.enclaveIdentity,
      qeReport: qeReport!,
    });
    expect(qeIdentityEvaluation.mrsignerMatch).toBe(false);
    expect(qeIdentityEvaluation.acceptable).toBe(false);
    expect(qeIdentityEvaluation.status).toBe("UpToDate");

    const pckExtensions = parseIntelPckExtensions(pckChain.chain![0]!);
    expect(pckExtensions).toBeDefined();

    const tcbEvaluation = evaluateTcbInfo({
      pckExtensions: pckExtensions!,
      quoteMrSignerSeam: quote!.mrSignerSeam,
      quoteSeamAttributes: quote!.seamAttributes,
      quoteTeeTcbSvn: quote!.teeTcbSvn,
      tcbInfo: INTEL_TDX_TCB_INFO.tcbInfo,
    });
    expect(tcbEvaluation.acceptable).toBe(true);
    expect(tcbEvaluation.status).toBe("UpToDate");
  });

  it("accepts a QE report when every signed collateral field matches", () => {
    const quote = decodeTdxQuote(INTEL_TDX_QUOTE_HEX)!;
    const qeReport = parseQeReport(quote.qeReport!);

    const qeIdentityEvaluation = evaluateQeIdentity({
      qeIdentity: INTEL_TDX_QE_IDENTITY.enclaveIdentity,
      qeReport: {
        ...qeReport!,
        mrsigner: INTEL_TDX_QE_IDENTITY.enclaveIdentity.mrsigner.toLowerCase(),
      },
    });

    expect(qeIdentityEvaluation.mrsignerMatch).toBe(true);
    expect(qeIdentityEvaluation.acceptable).toBe(true);
    expect(qeIdentityEvaluation.status).toBe("UpToDate");
  });

  it("rejects a tampered QE identity signature", async () => {
    const tcbSigningChain = await validateCertificateChain({
      bundle: INTEL_TDX_TCB_SIGN_CHAIN,
      bundleLabel: "Intel TCB signing chain",
      domain: "intel",
      jsonPath: "$.intel.tcbSignChain",
    });

    const badSignature = `${INTEL_TDX_QE_IDENTITY.signature.slice(0, -2)}00`;
    const signatureValid = await verifyIntelCollateralSignature({
      body: INTEL_TDX_QE_IDENTITY.enclaveIdentity,
      chain: tcbSigningChain.chain!,
      signatureHex: badSignature,
    });

    expect(signatureValid).toBe(false);
  });

  it("uses the original signed Intel body bytes when object keys are reordered", async () => {
    const tcbSigningChain = await validateCertificateChain({
      bundle: INTEL_TDX_TCB_SIGN_CHAIN,
      bundleLabel: "Intel TCB signing chain",
      domain: "intel",
      jsonPath: "$.intel.tcbSignChain",
    });

    const reorderedQeIdentity = {
      attributes: INTEL_TDX_QE_IDENTITY.enclaveIdentity.attributes,
      attributesMask: INTEL_TDX_QE_IDENTITY.enclaveIdentity.attributesMask,
      id: INTEL_TDX_QE_IDENTITY.enclaveIdentity.id,
      isvprodid: INTEL_TDX_QE_IDENTITY.enclaveIdentity.isvprodid,
      issueDate: INTEL_TDX_QE_IDENTITY.enclaveIdentity.issueDate,
      miscselect: INTEL_TDX_QE_IDENTITY.enclaveIdentity.miscselect,
      miscselectMask: INTEL_TDX_QE_IDENTITY.enclaveIdentity.miscselectMask,
      mrsigner: INTEL_TDX_QE_IDENTITY.enclaveIdentity.mrsigner,
      nextUpdate: INTEL_TDX_QE_IDENTITY.enclaveIdentity.nextUpdate,
      tcbEvaluationDataNumber:
        INTEL_TDX_QE_IDENTITY.enclaveIdentity.tcbEvaluationDataNumber,
      tcbLevels: INTEL_TDX_QE_IDENTITY.enclaveIdentity.tcbLevels,
      version: INTEL_TDX_QE_IDENTITY.enclaveIdentity.version,
    };

    const signatureFailsWithReorderedBody = await verifyIntelCollateralSignature({
      body: reorderedQeIdentity,
      chain: tcbSigningChain.chain!,
      signatureHex: INTEL_TDX_QE_IDENTITY.signature,
    });
    expect(signatureFailsWithReorderedBody).toBe(false);

    const originalSignedBodyText = extractIntelSignedBodyText(
      JSON.stringify(INTEL_TDX_QE_IDENTITY),
      "enclaveIdentity",
    );
    expect(originalSignedBodyText).toBeDefined();

    const signatureValidWithOriginalBody = await verifyIntelCollateralSignature({
      body: reorderedQeIdentity,
      chain: tcbSigningChain.chain!,
      signedBodyText: originalSignedBodyText,
      signatureHex: INTEL_TDX_QE_IDENTITY.signature,
    });

    expect(signatureValidWithOriginalBody).toBe(true);
  });

  it("fails TCB evaluation when the collateral FMSPC is wrong", async () => {
    const quote = decodeTdxQuote(INTEL_TDX_QUOTE_HEX)!;
    const pckChain = await validateCertificateChain({
      bundle: quote.certificationData!,
      bundleLabel: "Intel PCK certificate chain",
      domain: "intel",
      jsonPath: "$.intel_quote",
    });
    const pckExtensions = parseIntelPckExtensions(pckChain.chain![0]!);

    const tcbEvaluation = evaluateTcbInfo({
      pckExtensions: pckExtensions!,
      quoteMrSignerSeam: quote.mrSignerSeam,
      quoteSeamAttributes: quote.seamAttributes,
      quoteTeeTcbSvn: quote.teeTcbSvn,
      tcbInfo: {
        ...INTEL_TDX_TCB_INFO.tcbInfo,
        fmspc: "000000000000",
      },
    });

    expect(tcbEvaluation.fmspcMatch).toBe(false);
    expect(tcbEvaluation.acceptable).toBe(false);
  });

  it("treats expired collateral as not current", () => {
    expect(
      isCollateralCurrent({
        issueDate: "2021-08-06T13:55:15Z",
        nextUpdate: "2021-08-07T13:55:15Z",
      }, new Date("2026-03-12T00:00:00Z")),
    ).toBe(false);
  });
});
