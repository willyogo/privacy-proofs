export const NVIDIA_PROXY_BASE_ROUTE = "/api/nvidia";
export const NVIDIA_ATTEST_ROUTE = `${NVIDIA_PROXY_BASE_ROUTE}/attest/gpu`;
export const NVIDIA_JWKS_ROUTE = `${NVIDIA_PROXY_BASE_ROUTE}/jwks`;

const NVIDIA_ATTEST_URL = "https://nras.attestation.nvidia.com/v4/attest/gpu";
const NVIDIA_JWKS_URL =
  "https://nras.attestation.nvidia.com/.well-known/jwks.json";

const FORWARDED_NVIDIA_REQUEST_HEADERS = [
  "authorization",
  "x-api-key",
  "accept",
  "content-type",
] as const;

const FORWARDED_NVIDIA_RESPONSE_HEADERS = [
  "cache-control",
  "content-length",
  "content-type",
  "etag",
  "expires",
  "last-modified",
  "www-authenticate",
] as const;

export async function proxyNvidiaAttestationRequest({
  body,
  headers,
  method,
}: {
  body?: BodyInit | null;
  headers?:
    | HeadersInit
    | Record<string, string | string[] | undefined>;
  method?: string;
}): Promise<Response> {
  if (method && method !== "POST") {
    return new Response("Method Not Allowed", {
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
      status: 405,
    });
  }

  const upstreamHeaders = forwardNvidiaRequestHeaders(headers);
  if (!upstreamHeaders.has("accept")) {
    upstreamHeaders.set("accept", "application/json");
  }
  if (!upstreamHeaders.has("content-type")) {
    upstreamHeaders.set("content-type", "application/json");
  }

  const upstreamResponse = await fetch(NVIDIA_ATTEST_URL, {
    body,
    headers: upstreamHeaders,
    method: "POST",
  });

  return buildNvidiaProxyResponse(upstreamResponse, "nvidia-attest-proxy");
}

export async function proxyNvidiaJwksRequest(): Promise<Response> {
  const upstreamResponse = await fetch(NVIDIA_JWKS_URL, {
    headers: {
      accept: "application/json",
    },
    method: "GET",
  });

  return buildNvidiaProxyResponse(upstreamResponse, "nvidia-jwks-proxy");
}

function buildNvidiaProxyResponse(
  upstreamResponse: Response,
  proxyLabel: string,
): Response {
  const headers = new Headers();
  headers.set("x-proxied-by", proxyLabel);

  for (const headerName of FORWARDED_NVIDIA_RESPONSE_HEADERS) {
    const headerValue = upstreamResponse.headers.get(headerName);
    if (headerValue) {
      headers.set(headerName, headerValue);
    }
  }

  return new Response(upstreamResponse.body, {
    headers,
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
  });
}

function forwardNvidiaRequestHeaders(
  source?:
    | HeadersInit
    | Record<string, string | string[] | undefined>,
): Headers {
  const incomingHeaders = new Headers(normalizeProxyHeaders(source));
  const forwardedHeaders = new Headers();

  for (const headerName of FORWARDED_NVIDIA_REQUEST_HEADERS) {
    const headerValue = incomingHeaders.get(headerName);
    if (headerValue) {
      forwardedHeaders.set(headerName, headerValue);
    }
  }

  return forwardedHeaders;
}

function normalizeProxyHeaders(
  source?:
    | HeadersInit
    | Record<string, string | string[] | undefined>,
): HeadersInit | undefined {
  if (!source) {
    return undefined;
  }

  if (source instanceof Headers || Array.isArray(source)) {
    return source;
  }

  const entries: Array<[string, string]> = [];
  for (const [key, value] of Object.entries(source)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        entries.push([key, item]);
      }
      continue;
    }

    if (typeof value === "string") {
      entries.push([key, value]);
    }
  }

  return entries;
}
