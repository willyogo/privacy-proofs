import { proxyIntelCollateralRequest } from "../src/lib/intel-collateral-proxy";

export const runtime = "nodejs";

type NodeRequestLike = {
  query?: Record<string, string | string[] | undefined>;
  url?: string;
};

type NodeResponseLike = {
  end: (body?: Uint8Array | string) => void;
  setHeader: (name: string, value: string) => void;
  statusCode: number;
  statusMessage?: string;
};

export default async function handler(
  request: NodeRequestLike,
  response: NodeResponseLike,
) {
  const rawTarget =
    typeof request.query?.url === "string"
      ? request.query.url
      : getUrlSearchParam(request.url, "url");
  const upstreamResponse = await proxyIntelCollateralRequest(rawTarget);

  response.statusCode = upstreamResponse.status;
  response.statusMessage = upstreamResponse.statusText;
  upstreamResponse.headers.forEach((headerValue, headerName) => {
    response.setHeader(headerName, headerValue);
  });

  const body = new Uint8Array(await upstreamResponse.arrayBuffer());
  response.end(body);
}

function getUrlSearchParam(
  requestUrl: string | undefined,
  key: string,
): string | null {
  if (!requestUrl) {
    return null;
  }

  return new URL(requestUrl, "http://127.0.0.1").searchParams.get(key);
}
