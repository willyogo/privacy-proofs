export const INTEL_PROXY_ROUTE = "/intel-proxy";

const ALLOWED_INTEL_ORIGINS = new Set([
  "https://api.trustedservices.intel.com",
  "https://certificates.trustedservices.intel.com",
]);

const FORWARDED_RESPONSE_HEADERS = [
  "cache-control",
  "content-length",
  "content-type",
  "etag",
  "expires",
  "last-modified",
  "sgx-enclave-identity-issuer-chain",
  "sgx-pck-crl-issuer-chain",
  "tcb-info-issuer-chain",
] as const;

const INTEL_ACCEPT_HEADER =
  "application/json, application/x-pem-file, application/pkix-crl, text/plain;q=0.9, */*;q=0.1";

export async function proxyIntelCollateralRequest(
  rawTarget: string | null | undefined,
): Promise<Response> {
  const targetResult = parseIntelCollateralTarget(rawTarget);
  if ("error" in targetResult) {
    return new Response(targetResult.error.message, {
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
      status: targetResult.error.status,
    });
  }

  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetch(targetResult.targetUrl, {
      headers: {
        accept: INTEL_ACCEPT_HEADER,
      },
      method: "GET",
    });
  } catch (error) {
    return new Response(buildProxyErrorMessage(error), {
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
      status: 502,
    });
  }

  const headers = new Headers();
  headers.set("x-proxied-by", "intel-collateral-proxy");

  for (const headerName of FORWARDED_RESPONSE_HEADERS) {
    const headerValue = upstreamResponse.headers.get(headerName);
    if (headerValue) {
      headers.set(headerName, headerValue);
    }
  }

  return new Response(await upstreamResponse.arrayBuffer(), {
    headers,
    status: upstreamResponse.status,
  });
}

function buildProxyErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return `Intel collateral proxy request failed: ${error.message}`;
  }

  return "Intel collateral proxy request failed";
}

function parseIntelCollateralTarget(
  rawTarget: string | null | undefined,
):
  | {
      error: {
        message: string;
        status: number;
      };
    }
  | {
      targetUrl: URL;
    } {
  if (!rawTarget) {
    return {
      error: {
        message: "Missing Intel collateral URL",
        status: 400,
      },
    };
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(rawTarget);
  } catch {
    return {
      error: {
        message: "Invalid Intel collateral URL",
        status: 400,
      },
    };
  }

  if (
    targetUrl.protocol !== "https:" ||
    !ALLOWED_INTEL_ORIGINS.has(targetUrl.origin)
  ) {
    return {
      error: {
        message: "Blocked Intel collateral host",
        status: 403,
      },
    };
  }

  return { targetUrl };
}
