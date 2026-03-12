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
      summary: {
        eventNames: [],
        model: "fixture-model",
        preview: {},
        teeHardware: "TDX",
        topLevelKeys: ["report"],
        verifiedAt: "2026-03-12T01:02:03Z",
      },
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

  it("renders the polished section headings in the expected order", async () => {
    const { default: App } = await import("../src/app");
    render(<App />);

    const headings = screen.getAllByRole("heading", { level: 2 }).map((heading) => {
      return heading.textContent;
    });

    expect(headings).toEqual([
      "Load a report and verify",
      "Ready to Verify",
      "Current Checks",
      "Decoded Overview",
    ]);
  });

  it("starts with compact textareas and expands verdict details after verification", async () => {
    const { default: App } = await import("../src/app");
    render(<App />);

    const reportTextarea = screen.getByLabelText(
      "Raw attestation JSON",
    ) as HTMLTextAreaElement;
    const collateralTextarea = screen.getByLabelText(
      "Optional collateral bundle JSON",
    ) as HTMLTextAreaElement;

    expect(reportTextarea.rows).toBe(2);
    expect(collateralTextarea.rows).toBe(2);
    expect(screen.queryByText("Source")).toBeNull();
    expect(screen.queryByText("fixture-model")).toBeNull();

    fireEvent.change(reportTextarea, {
      target: { value: '{"report":true}' },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify report" }));

    await waitFor(() => expect(screen.getByText("Source")).toBeTruthy());
    expect(screen.getByText("fixture-model")).toBeTruthy();
  });
});
