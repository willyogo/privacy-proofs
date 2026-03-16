import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ParseResult } from "../src/lib/types";

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
    parseReportSource.mockResolvedValue(buildResult());
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
    parseReportSource
      .mockResolvedValueOnce(buildUnauthorizedResult())
      .mockResolvedValueOnce(buildResult());
    render(<App />);

    expect(screen.queryByRole("link", { name: "NVIDIA API key" })).toBeNull();

    fireEvent.change(screen.getByLabelText("Raw attestation JSON"), {
      target: { value: '{"report":true}' },
    });

    fireEvent.click(
      screen.getByRole("button", { name: "Complete full verification" }),
    );

    await waitFor(() => expect(parseReportSource).toHaveBeenCalledTimes(1));
    expect(parseReportSource).toHaveBeenCalledWith('{"report":true}', undefined, {
      mode: "online",
      online: {
        intelBaseUrl: "/intel-proxy",
        nvidiaApiKey: undefined,
        nvidiaBaseUrl: "/nvidia",
        nvidiaJwksUrl: "/nvidia/jwks",
      },
    });

    const nvidiaApiKeyLink = await screen.findByRole("link", {
      name: "NVIDIA API key",
    });
    expect(nvidiaApiKeyLink.getAttribute("href")).toBe("https://build.nvidia.com/");
    expect(nvidiaApiKeyLink.getAttribute("target")).toBe("_blank");

    fireEvent.change(
      screen.getByLabelText(
        "NVIDIA API key (shown because NRAS rejected the unauthenticated request)",
      ),
      {
        target: { value: "fixture-api-key" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Complete full verification" }),
    );

    await waitFor(() => expect(parseReportSource).toHaveBeenCalledTimes(2));
    expect(parseReportSource).toHaveBeenLastCalledWith('{"report":true}', undefined, {
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

function buildResult(checks: ParseResult["checks"] = []): ParseResult {
  return {
    checks,
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
      consistencyFailures: 0,
      cryptographicStatus: "partial",
      description: "fixture result",
      engineLabel: "Engine active",
      evidenceStatus: {
        intel: "partial",
        nvidia: "partial",
      },
      failedChecks: 0,
      headline: "Partial verification",
      infoChecks: 0,
      intelRevocationCoverage: "not-run",
      mode: "offline",
      passedChecks: 1,
      status: "partially-verified",
      supportedChecks: 1,
    },
  };
}

function buildUnauthorizedResult(): ParseResult {
  return buildResult([
    {
      authority: "vendor",
      description: "The NVIDIA NRAS request failed with HTTP 401.",
      details: [
        {
          label: "HTTP status",
          value: "401",
        },
      ],
      domain: "nvidia",
      id: "nvidia-online-attest-fetch",
      jsonPath: "$.nvidia_payload",
      label: "Submit NVIDIA evidence to NRAS",
      severity: "advisory",
      source: "online",
      status: "fail",
    },
  ]);
}
