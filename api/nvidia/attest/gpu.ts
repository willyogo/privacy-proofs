import { proxyNvidiaAttestationRequest } from "../../../src/lib/nvidia-collateral-proxy.js";

export const runtime = "nodejs";

export default {
  async fetch(request: Request) {
    const body = request.body ? await request.arrayBuffer() : undefined;
    return proxyNvidiaAttestationRequest({
      body,
      headers: request.headers,
      method: request.method,
    });
  },
};
