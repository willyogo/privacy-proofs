import { afterEach, describe, expect, it, vi } from "vitest";
import {
  proxyNvidiaAttestationRequest,
  proxyNvidiaJwksRequest,
} from "../src/lib/nvidia-collateral-proxy";

describe("nvidia collateral proxy", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("forwards attestation requests with the supported auth headers", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response('{"ok":true}', {
        headers: {
          "content-type": "application/json",
          "www-authenticate": "fixture-auth",
        },
        status: 200,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await proxyNvidiaAttestationRequest({
      body: '{"nonce":"fixture"}',
      headers: {
        authorization: "nvapi-fixture",
        "content-type": "application/json",
        "x-api-key": "ignored-fixture",
      },
      method: "POST",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, init] = fetchMock.mock.calls[0]!;
    expect(String(targetUrl)).toBe(
      "https://nras.attestation.nvidia.com/v4/attest/gpu",
    );
    expect(init).toMatchObject({
      body: '{"nonce":"fixture"}',
      method: "POST",
    });
    const forwardedHeaders = new Headers(init?.headers);
    expect(forwardedHeaders.get("authorization")).toBe("nvapi-fixture");
    expect(forwardedHeaders.get("x-api-key")).toBe("ignored-fixture");
    expect(forwardedHeaders.get("content-type")).toBe("application/json");

    expect(response.status).toBe(200);
    expect(response.headers.get("x-proxied-by")).toBe("nvidia-attest-proxy");
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("www-authenticate")).toBe("fixture-auth");
    expect(await response.text()).toBe('{"ok":true}');
  });

  it("fetches NVIDIA JWKS through the proxy", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response('{"keys":[]}', {
        headers: {
          "content-type": "application/json",
        },
        status: 200,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await proxyNvidiaJwksRequest();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [targetUrl, init] = fetchMock.mock.calls[0]!;
    expect(String(targetUrl)).toBe(
      "https://nras.attestation.nvidia.com/.well-known/jwks.json",
    );
    expect(init).toMatchObject({
      headers: {
        accept: "application/json",
      },
      method: "GET",
    });
    expect(response.headers.get("x-proxied-by")).toBe("nvidia-jwks-proxy");
    expect(await response.text()).toBe('{"keys":[]}');
  });
});
