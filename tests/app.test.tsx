import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const parseReportSource = vi.fn();

vi.mock("../src/lib/normalize", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/normalize")>(
    "../src/lib/normalize",
  );

  return {
    ...actual,
    parseReportSource,
  };
});

describe("App", () => {
  beforeEach(() => {
    parseReportSource.mockReset();
    parseReportSource.mockResolvedValue({
      checks: [],
      state: "loaded",
      verification: {
        badge: "Partially verified",
        collateralStatus: "missing",
        cryptographicStatus: "partial",
        description: "fixture result",
        engineLabel: "Engine active",
        failedChecks: 0,
        headline: "Partial verification",
        infoChecks: 0,
        mode: "offline",
        passedChecks: 1,
        status: "partially-verified",
        supportedChecks: 1,
      },
    });
  });

  it("does not verify on every keystroke and runs verification on button click", async () => {
    const { default: App } = await import("../src/app");
    render(<App />);

    fireEvent.change(screen.getByLabelText("Raw attestation JSON"), {
      target: { value: '{"report":true}' },
    });

    expect(parseReportSource).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Verify report" }));

    await waitFor(() => expect(parseReportSource).toHaveBeenCalledTimes(1));
  });
});
