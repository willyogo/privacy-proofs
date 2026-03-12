import { proxyNvidiaJwksRequest } from "../../src/lib/nvidia-collateral-proxy";

type NodeResponseLike = {
  end: (body?: Uint8Array | string) => void;
  setHeader: (name: string, value: string) => void;
  statusCode: number;
  statusMessage?: string;
};

export const runtime = "nodejs";

export default async function handler(
  _request: unknown,
  response: NodeResponseLike,
) {
  const upstreamResponse = await proxyNvidiaJwksRequest();
  response.statusCode = upstreamResponse.status;
  response.statusMessage = upstreamResponse.statusText;
  upstreamResponse.headers.forEach((headerValue, headerName) => {
    response.setHeader(headerName, headerValue);
  });

  const body = new Uint8Array(await upstreamResponse.arrayBuffer());
  response.end(body);
}
