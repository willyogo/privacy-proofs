import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import {
  INTEL_PROXY_ROUTE,
  proxyIntelCollateralRequest,
} from "./src/lib/intel-collateral-proxy";
import {
  NVIDIA_ATTEST_ROUTE,
  NVIDIA_JWKS_ROUTE,
  proxyNvidiaAttestationRequest,
  proxyNvidiaJwksRequest,
} from "./src/lib/nvidia-collateral-proxy";

function intelCollateralProxyPlugin() {
  const handleRequest = async (
    req: {
      headers?: Record<string, string | string[] | undefined>;
      method?: string;
      url?: string;
      [Symbol.asyncIterator]?: () => AsyncIterator<Uint8Array | string>;
    },
    res: {
      end: (body?: Uint8Array | string) => void;
      setHeader: (name: string, value: string) => void;
      statusCode: number;
    },
    next: (error?: unknown) => void,
  ) => {
    const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");
    if (
      requestUrl.pathname !== INTEL_PROXY_ROUTE &&
      requestUrl.pathname !== NVIDIA_ATTEST_ROUTE &&
      requestUrl.pathname !== NVIDIA_JWKS_ROUTE
    ) {
      next();
      return;
    }

    if (
      requestUrl.pathname === INTEL_PROXY_ROUTE &&
      req.method &&
      req.method !== "GET"
    ) {
      res.statusCode = 405;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end("Method Not Allowed");
      return;
    }

    try {
      const upstreamResponse =
        requestUrl.pathname === INTEL_PROXY_ROUTE
          ? await proxyIntelCollateralRequest(requestUrl.searchParams.get("url"))
          : requestUrl.pathname === NVIDIA_ATTEST_ROUTE
            ? await proxyNvidiaAttestationRequest({
                body: await readRequestBody(req),
                headers: req.headers,
                method: req.method,
              })
            : await proxyNvidiaJwksRequest();

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

async function readRequestBody(
  req: {
    [Symbol.asyncIterator]?: () => AsyncIterator<Uint8Array | string>;
  },
): Promise<ArrayBuffer | undefined> {
  if (!req[Symbol.asyncIterator]) {
    return undefined;
  }

  const chunks: Uint8Array[] = [];
  const iterable = req as AsyncIterable<Uint8Array | string>;
  for await (const chunk of iterable) {
    chunks.push(
      typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk,
    );
  }

  if (chunks.length === 0) {
    return undefined;
  }

  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }

  return Uint8Array.from(output).buffer;
}

export default defineConfig({
  plugins: [react(), intelCollateralProxyPlugin()],
  test: {
    environment: "jsdom",
    globals: true,
  },
});
