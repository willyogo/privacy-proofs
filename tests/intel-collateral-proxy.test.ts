import { afterEach, describe, expect, it, vi } from "vitest";
import { proxyIntelCollateralRequest } from "../src/lib/intel-collateral-proxy";

describe("intel collateral proxy", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("blocks non-Intel hosts", async () => {
    const response = await proxyIntelCollateralRequest(
      "https://example.com/collateral",
    );

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("Blocked Intel collateral host");
  });

  it("forwards allowed Intel responses and issuer headers", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response("fixture-body", {
        headers: {
          "content-type": "application/json",
          "tcb-info-issuer-chain": "fixture-chain",
          "x-ignored": "ignore-me",
        },
        status: 200,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await proxyIntelCollateralRequest(
      "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, init] = fetchMock.mock.calls[0]!;
    expect(String(targetUrl)).toBe(
      "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
    );
    expect(init).toMatchObject({
      headers: {
        accept:
          "application/json, application/x-pem-file, application/pkix-crl, text/plain;q=0.9, */*;q=0.1",
      },
      method: "GET",
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("x-proxied-by")).toBe(
      "intel-collateral-proxy",
    );
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("tcb-info-issuer-chain")).toBe(
      "fixture-chain",
    );
    expect(response.headers.get("x-ignored")).toBeNull();
    expect(await response.text()).toBe("fixture-body");
  });
});
