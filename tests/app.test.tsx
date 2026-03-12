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

    fireEvent.click(screen.getByRole("button", { name: "Verify locally" }));

    await waitFor(() => expect(parseReportSource).toHaveBeenCalledTimes(1));
    expect(parseReportSource).toHaveBeenCalledWith('{"report":true}', undefined, {
      mode: "offline",
      online: undefined,
    });
  });

  it("renders the polished section headings in the expected order", async () => {
    const { default: App } = await import("../src/app");
    render(<App />);

    expect(screen.queryByText(/^Input$/)).toBeNull();
    expect(screen.queryByText(/^Diagnostics$/)).toBeNull();
    expect(screen.queryByText(/^Advanced$/)).toBeNull();

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

    expect(reportTextarea.rows).toBe(2);
    expect(screen.queryByText("Collateral")).toBeNull();
    expect(screen.queryByLabelText("Optional collateral bundle JSON")).toBeNull();
    expect(screen.queryByText("Source")).toBeNull();
    expect(screen.queryByText("fixture-model")).toBeNull();

    fireEvent.change(reportTextarea, {
      target: { value: '{"report":true}' },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify locally" }));

    await waitFor(() => expect(screen.getByText("Source")).toBeTruthy());
    expect(screen.getByText("fixture-model")).toBeTruthy();
  });

  it("passes online options when full verification is requested", async () => {
    const { default: App } = await import("../src/app");
    render(<App />);

    const nvidiaApiKeyLink = screen.getByRole("link", { name: "NVIDIA API key" });
    expect(nvidiaApiKeyLink.getAttribute("href")).toBe("https://build.nvidia.com/");
    expect(nvidiaApiKeyLink.getAttribute("target")).toBe("_blank");

    fireEvent.change(screen.getByLabelText("Raw attestation JSON"), {
      target: { value: '{"report":true}' },
    });
    fireEvent.change(
      screen.getByLabelText(
        "NVIDIA API key (optional for local verification, required for live vendor verification)",
      ),
      {
        target: { value: "fixture-api-key" },
      },
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Complete full verification" }),
    );

    await waitFor(() => expect(parseReportSource).toHaveBeenCalledTimes(1));
    expect(parseReportSource).toHaveBeenCalledWith('{"report":true}', undefined, {
      mode: "online",
      online: {
        intelBaseUrl: "/intel-proxy",
        nvidiaApiKey: "fixture-api-key",
        nvidiaBaseUrl: "/nvidia",
        nvidiaJwksUrl: "/nvidia/jwks",
      },
    });
  });
});
