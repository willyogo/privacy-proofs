import { proxyNvidiaAttestationRequest } from "../../../src/lib/nvidia-collateral-proxy";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = request.body ? await request.arrayBuffer() : undefined;
  return proxyNvidiaAttestationRequest({
    body,
    headers: request.headers,
    method: request.method,
  });
}
