import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseReportSource } from "../src/lib/normalize";

const SAMPLE_REPORT_PATH =
  "/Users/willy/Downloads/attestation-e2ee-deepseek-v3-1-1773243769002.json";

describe("parseReportSource", () => {
  it("returns an error for invalid JSON", () => {
    const result = parseReportSource("{broken");

    expect(result.state).toBe("error");
    expect(result.checks[0]?.status).toBe("fail");
    expect(result.verification.status).toBe("invalid");
  });

  it("flags missing required fields", () => {
    const result = parseReportSource(
      JSON.stringify({
        info: {},
      }),
    );

    expect(result.state).toBe("error");
    expect(
      result.checks.find((check) => check.id === "required-fields")?.status,
    ).toBe("fail");
  });

  it("verifies the provided sample report", () => {
    if (!existsSync(SAMPLE_REPORT_PATH)) {
      return;
    }

    const result = parseReportSource(
      readFileSync(SAMPLE_REPORT_PATH, "utf8"),
      "sample.json",
    );

    expect(result.verification.status).toBe("verified");
    expect(result.summary?.derivedSigningAddress).toBe(
      "0x4B19f7f8Fd7757AAb29a8990bb11f6aA3572C9B1",
    );
    expect(result.summary?.quoteReportData).toContain(
      "4b19f7f8fd7757aab29a8990bb11f6aa3572c9b1",
    );
    expect(result.checks.some((check) => check.status === "fail")).toBe(false);
  });

  it("fails verification when the nonce is tampered", () => {
    if (!existsSync(SAMPLE_REPORT_PATH)) {
      return;
    }

    const report = JSON.parse(readFileSync(SAMPLE_REPORT_PATH, "utf8")) as Record<
      string,
      unknown
    >;
    report.nonce =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const result = parseReportSource(JSON.stringify(report), "tampered.json");

    expect(result.verification.status).toBe("invalid");
    expect(
      result.checks.find((check) => check.id === "request-nonce-consistency")
        ?.status,
    ).toBe("fail");
  });
});
