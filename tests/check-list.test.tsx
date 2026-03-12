import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import CheckList from "../src/components/CheckList";
import type { CheckResult } from "../src/lib/check-result";
import type { NormalizedAttestationReport, VerificationSummary } from "../src/lib/types";

describe("CheckList", () => {
  const writeText = vi.fn();

  beforeEach(() => {
    writeText.mockReset();
    writeText.mockResolvedValue(undefined);

    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: {
        writeText,
      },
    });
  });

  it("keeps one clicked diagnostics popover open at a time", () => {
    renderChecklist();

    fireEvent.click(
      screen.getByRole("button", { name: /Verify signing public key binding/ }),
    );

    expect(
      screen.getByRole("dialog", { name: /Verify signing public key binding details/ }),
    ).toBeTruthy();

    fireEvent.click(
      screen.getByRole("button", { name: /Inspect embedded binding claims/ }),
    );

    expect(
      screen.queryByRole("dialog", { name: /Verify signing public key binding details/ }),
    ).toBeNull();
    expect(
      screen.getByRole("dialog", { name: /Inspect embedded binding claims details/ }),
    ).toBeTruthy();
  });

  it("closes the pinned popover on outside click and Escape", () => {
    renderChecklist();

    fireEvent.click(
      screen.getByRole("button", { name: /Verify signing public key binding/ }),
    );
    fireEvent.mouseDown(document.body);

    expect(
      screen.queryByRole("dialog", { name: /Verify signing public key binding details/ }),
    ).toBeNull();

    fireEvent.click(
      screen.getByRole("button", { name: /Verify signing public key binding/ }),
    );
    fireEvent.keyDown(document, { key: "Escape" });

    expect(
      screen.queryByRole("dialog", { name: /Verify signing public key binding details/ }),
    ).toBeNull();
  });

  it("shows resolved raw data and copies the full raw value and path", async () => {
    const { report } = renderChecklist();

    fireEvent.click(
      screen.getByRole("button", { name: /Verify signing public key binding/ }),
    );

    expect(screen.getByText("Reported signing address")).toBeTruthy();
    expect(screen.getByText("$.signing_public_key")).toBeTruthy();
    expect(screen.getByText(/Showing an excerpt of/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Copy value" }));
    fireEvent.click(screen.getByRole("button", { name: "Copy path" }));

    await waitFor(() => {
      expect(writeText).toHaveBeenNthCalledWith(1, report.signing_public_key);
      expect(writeText).toHaveBeenNthCalledWith(2, "$.signing_public_key");
    });

    expect(
      screen.getByRole("dialog", { name: /Verify signing public key binding details/ }),
    ).toBeTruthy();
  });
});

function renderChecklist() {
  const report = buildReport();

  render(
    <CheckList
      checks={buildChecks()}
      report={report}
      verification={buildVerification()}
    />,
  );

  return { report };
}

function buildChecks(): CheckResult[] {
  return [
    {
      description: "The signing public key derives to the reported Ethereum address.",
      details: [
        {
          copyValue: "0x1234",
          label: "Reported signing address",
          value: "0x1234",
        },
        {
          copyValue: "0x1234",
          label: "Derived address from public key",
          value: "0x1234",
        },
      ],
      domain: "binding",
      id: "signing-address-binding",
      jsonPath: "$.signing_public_key",
      label: "Verify signing public key binding",
      severity: "blocking",
      source: "local",
      status: "pass",
    },
    {
      description:
        "The embedded verifier does not provide a matching signing address binding.",
      details: [
        {
          copyValue: "0x1234",
          label: "Embedded report-data address",
          value: "0x1234",
        },
        {
          copyValue: "0x5678",
          label: "Locally derived signing address",
          value: "0x5678",
        },
      ],
      domain: "provenance",
      id: "embedded-binding-claims",
      jsonPath: "$.server_verification",
      label: "Inspect embedded binding claims",
      severity: "advisory",
      source: "embedded",
      status: "info",
    },
  ];
}

function buildVerification(): VerificationSummary {
  return {
    badge: "Verified",
    cryptographicStatus: "verified",
    description: "fixture result",
    engineLabel: "Engine active",
    evidenceStatus: {
      intel: "verified",
      nvidia: "verified",
    },
    failedChecks: 0,
    headline: "Attestation verified",
    infoChecks: 1,
    mode: "offline",
    passedChecks: 1,
    status: "verified",
    supportedChecks: 1,
  };
}

function buildReport(): NormalizedAttestationReport {
  return {
    event_log: [],
    info: {},
    intel_quote: "00",
    nonce: "0xaaaa",
    nvidia_payload: {
      arch: "H100",
      evidence_list: [
        {
          arch: "H100",
          certificate: "cert",
          evidence: "evidence",
        },
      ],
      nonce: "0xbbbb",
    },
    request_nonce: "0xaaaa",
    server_verification: {
      signingAddressBinding: {
        reportDataAddress: "0x1234",
      },
      verifiedAt: "2026-03-12T01:02:03Z",
    },
    signing_address: "0x1234",
    signing_public_key: `04${"ab".repeat(220)}`,
    tee_hardware: "intel-tdx",
    tee_provider: "near-ai",
  };
}
