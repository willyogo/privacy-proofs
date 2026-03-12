import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const INTEL_PROXY_ROUTE = "/api/intel-proxy";
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
];

function intelCollateralProxyPlugin() {
  const handleRequest = async (
    req: { method?: string; url?: string },
    res: {
      end: (body?: Uint8Array | string) => void;
      setHeader: (name: string, value: string) => void;
      statusCode: number;
    },
    next: (error?: unknown) => void,
  ) => {
    const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");
    if (requestUrl.pathname !== INTEL_PROXY_ROUTE) {
      next();
      return;
    }

    if (req.method && req.method !== "GET") {
      res.statusCode = 405;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end("Method Not Allowed");
      return;
    }

    const rawTarget = requestUrl.searchParams.get("url");
    if (!rawTarget) {
      res.statusCode = 400;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end("Missing Intel collateral URL");
      return;
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(rawTarget);
    } catch {
      res.statusCode = 400;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end("Invalid Intel collateral URL");
      return;
    }

    if (
      targetUrl.protocol !== "https:" ||
      !ALLOWED_INTEL_ORIGINS.has(targetUrl.origin)
    ) {
      res.statusCode = 403;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end("Blocked Intel collateral host");
      return;
    }

    try {
      const upstreamResponse = await fetch(targetUrl, {
        headers: {
          accept:
            "application/json, application/x-pem-file, application/pkix-crl, text/plain;q=0.9, */*;q=0.1",
        },
        method: "GET",
      });

      res.statusCode = upstreamResponse.status;
      res.setHeader("x-proxied-by", "vite-intel-collateral-proxy");

      for (const headerName of FORWARDED_RESPONSE_HEADERS) {
        const headerValue = upstreamResponse.headers.get(headerName);
        if (headerValue) {
          res.setHeader(headerName, headerValue);
        }
      }

      const body = new Uint8Array(await upstreamResponse.arrayBuffer());
      res.end(body);
    } catch (error) {
      next(error);
    }
  };

  return {
    configurePreviewServer(server: {
      middlewares: {
        use: (
          handler: (
            req: { method?: string; url?: string },
            res: {
              end: (body?: Uint8Array | string) => void;
              setHeader: (name: string, value: string) => void;
              statusCode: number;
            },
            next: (error?: unknown) => void,
          ) => void | Promise<void>,
        ) => void;
      };
    }) {
      server.middlewares.use(handleRequest);
    },
    configureServer(server: {
      middlewares: {
        use: (
          handler: (
            req: { method?: string; url?: string },
            res: {
              end: (body?: Uint8Array | string) => void;
              setHeader: (name: string, value: string) => void;
              statusCode: number;
            },
            next: (error?: unknown) => void,
          ) => void | Promise<void>,
        ) => void;
      };
    }) {
      server.middlewares.use(handleRequest);
    },
    name: "intel-collateral-proxy",
  };
}

export default defineConfig({
  plugins: [react(), intelCollateralProxyPlugin()],
  test: {
    environment: "jsdom",
    globals: true,
  },
});
