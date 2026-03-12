import { proxyIntelCollateralRequest } from "../src/lib/intel-collateral-proxy";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const url = new URL(request.url);
  return proxyIntelCollateralRequest(url.searchParams.get("url"));
}

