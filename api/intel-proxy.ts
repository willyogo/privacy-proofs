import { proxyIntelCollateralRequest } from "../src/lib/intel-collateral-proxy.js";

export const runtime = "nodejs";

export default {
  async fetch(request: Request) {
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", {
        headers: {
          "content-type": "text/plain; charset=utf-8",
        },
        status: 405,
      });
    }

    const url = new URL(request.url);
    return proxyIntelCollateralRequest(url.searchParams.get("url"));
  },
};
