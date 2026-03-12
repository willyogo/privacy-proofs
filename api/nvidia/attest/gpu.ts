import { proxyNvidiaAttestationRequest } from "../../../src/lib/nvidia-collateral-proxy";

type NodeRequestLike = {
  body?: unknown;
  headers?: Record<string, string | string[] | undefined>;
  method?: string;
  [Symbol.asyncIterator]?: () => AsyncIterator<Uint8Array | string>;
};

type NodeResponseLike = {
  end: (body?: Uint8Array | string) => void;
  setHeader: (name: string, value: string) => void;
  statusCode: number;
  statusMessage?: string;
};

export const runtime = "nodejs";

export default async function handler(
  request: NodeRequestLike,
  response: NodeResponseLike,
) {
  const body = await normalizeNodeRequestBody(request);
  const upstreamResponse = await proxyNvidiaAttestationRequest({
    body,
    headers: request.headers,
    method: request.method,
  });

  await writeNodeResponse(response, upstreamResponse);
}

async function normalizeNodeRequestBody(
  request: NodeRequestLike,
): Promise<BodyInit | null | undefined> {
  if (typeof request.body === "string") {
    return request.body;
  }

  if (request.body instanceof Uint8Array) {
    return Uint8Array.from(request.body).buffer;
  }

  if (request.body && typeof request.body === "object") {
    return JSON.stringify(request.body);
  }

  if (!request[Symbol.asyncIterator]) {
    return undefined;
  }

  const chunks: Uint8Array[] = [];
  const iterable = request as AsyncIterable<Uint8Array | string>;
  for await (const chunk of iterable) {
    chunks.push(
      typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk,
    );
  }

  if (chunks.length === 0) {
    return undefined;
  }

  return concatBytes(chunks);
}

async function writeNodeResponse(
  response: NodeResponseLike,
  upstreamResponse: Response,
) {
  response.statusCode = upstreamResponse.status;
  response.statusMessage = upstreamResponse.statusText;
  upstreamResponse.headers.forEach((headerValue, headerName) => {
    response.setHeader(headerName, headerValue);
  });

  const body = new Uint8Array(await upstreamResponse.arrayBuffer());
  response.end(body);
}

function concatBytes(chunks: Uint8Array[]): ArrayBuffer {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }

  return Uint8Array.from(output).buffer;
}
