import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import VerdictCard from "../src/components/VerdictCard";
import type { ParseResult } from "../src/lib/types";

describe("VerdictCard", () => {
  it("formats embedded verification timestamps in readable UTC text", () => {
    render(
      <VerdictCard
        fileName="fixture.json"
        result={buildResult("2026-03-12T01:02:03Z")}
      />,
    );

    expect(screen.getByText(/Mar 12, 2026.*1:02:03 AM UTC/)).toBeTruthy();
  });

  it("falls back to the raw timestamp when formatting fails", () => {
    render(
      <VerdictCard
        fileName="fixture.json"
        result={buildResult("not-a-date")}
      />,
    );

    expect(screen.getByText("not-a-date")).toBeTruthy();
  });

  it("shows Unavailable when the report has no verification timestamp", () => {
    render(
      <VerdictCard
        fileName="fixture.json"
        result={buildResult()}
      />,
    );

    expect(screen.getByText("Unavailable")).toBeTruthy();
  });

  it("renders human-readable local-check and revocation labels", () => {
    render(
      <VerdictCard
        fileName="fixture.json"
        result={buildResult("2026-03-12T01:02:03Z", {
          consistencyFailures: 1,
          intelRevocationCoverage: "limited",
        })}
      />,
    );

    expect(screen.getByText("All supported local cryptographic checks passed")).toBeTruthy();
    expect(screen.getByText("1 failed consistency check")).toBeTruthy();
    expect(screen.getByText("Limited coverage")).toBeTruthy();
  });
});

function buildResult(
  verifiedAt?: string,
  overrides?: Partial<ParseResult["verification"]>,
): ParseResult {
  return {
    checks: [],
    state: "loaded",
    summary: {
      eventNames: [],
      model: "fixture-model",
      preview: {},
      teeHardware: "TDX",
      topLevelKeys: ["report"],
      verifiedAt,
    },
    verification: {
      badge: "Verified",
      consistencyFailures: 0,
      cryptographicStatus: "verified",
      description: "fixture result",
      engineLabel: "Engine active",
      evidenceStatus: {
        intel: "verified",
        nvidia: "verified",
      },
      failedChecks: 0,
      headline: "Attestation verified",
      infoChecks: 0,
      intelRevocationCoverage: "not-run",
      mode: "offline",
      passedChecks: 2,
      status: "verified",
      supportedChecks: 2,
      ...overrides,
    },
  };
}
