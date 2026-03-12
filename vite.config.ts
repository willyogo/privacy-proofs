import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import {
  INTEL_PROXY_ROUTE,
  proxyIntelCollateralRequest,
} from "./src/lib/intel-collateral-proxy";

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

    try {
      const upstreamResponse = await proxyIntelCollateralRequest(
        requestUrl.searchParams.get("url"),
      );

      res.statusCode = upstreamResponse.status;
      upstreamResponse.headers.forEach((headerValue, headerName) => {
        if (headerValue) {
          res.setHeader(headerName, headerValue);
        }
      });

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
