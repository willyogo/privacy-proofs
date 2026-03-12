import { proxyNvidiaJwksRequest } from "../../src/lib/nvidia-collateral-proxy";

export const runtime = "nodejs";

export async function GET() {
  return proxyNvidiaJwksRequest();
}
