import {
  type Connect,
  defineConfig,
  type Plugin,
  type PreviewServer,
  type ViteDevServer,
} from "vite";
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

type ProxyRequest = {
  headers?: Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
  [Symbol.asyncIterator]?: () => AsyncIterator<
    Uint8Array | string | ArrayBuffer | ArrayBufferView
  >;
};

type ProxyResponse = {
  end: (body?: Uint8Array | string) => void;
  setHeader: (name: string, value: string) => void;
  statusCode: number;
};

function intelCollateralProxyPlugin(): Plugin {
  const handleRequest: Connect.NextHandleFunction = async (req, res, next) => {
    const proxyReq = req as unknown as ProxyRequest;
    const proxyRes = res as unknown as ProxyResponse;
    const requestUrl = new URL(proxyReq.url ?? "/", "http://127.0.0.1");
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
      proxyReq.method &&
      proxyReq.method !== "GET"
    ) {
      proxyRes.statusCode = 405;
      proxyRes.setHeader("content-type", "text/plain; charset=utf-8");
      proxyRes.end("Method Not Allowed");
      return;
    }

    try {
      const upstreamResponse =
        requestUrl.pathname === INTEL_PROXY_ROUTE
          ? await proxyIntelCollateralRequest(requestUrl.searchParams.get("url"))
          : requestUrl.pathname === NVIDIA_ATTEST_ROUTE
            ? await proxyNvidiaAttestationRequest({
                body: await readRequestBody(proxyReq),
                headers: proxyReq.headers,
                method: proxyReq.method,
              })
            : await proxyNvidiaJwksRequest();

      proxyRes.statusCode = upstreamResponse.status;
      upstreamResponse.headers.forEach((headerValue, headerName) => {
        if (headerValue) {
          proxyRes.setHeader(headerName, headerValue);
        }
      });

      const body = new Uint8Array(await upstreamResponse.arrayBuffer());
      proxyRes.end(body);
    } catch (error) {
      next(error);
    }
  };

  return {
    configurePreviewServer(server: PreviewServer) {
      server.middlewares.use(handleRequest);
    },
    configureServer(server: ViteDevServer) {
      server.middlewares.use(handleRequest);
    },
    name: "intel-collateral-proxy",
  };
}

async function readRequestBody(
  req: ProxyRequest,
): Promise<ArrayBuffer | undefined> {
  if (!req[Symbol.asyncIterator]) {
    return undefined;
  }

  const chunks: Uint8Array[] = [];

  const iterable = req as AsyncIterable<
    Uint8Array | string | ArrayBuffer | ArrayBufferView
  >;
  for await (const chunk of iterable) {
    chunks.push(toUint8Array(chunk));
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

function toUint8Array(
  chunk: Uint8Array | string | ArrayBuffer | ArrayBufferView,
): Uint8Array {
  if (typeof chunk === "string") {
    return new TextEncoder().encode(chunk);
  }

  if (chunk instanceof Uint8Array) {
    return chunk;
  }

  if (chunk instanceof ArrayBuffer) {
    return new Uint8Array(chunk);
  }

  return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
}

export default defineConfig({
  plugins: [react(), intelCollateralProxyPlugin()],
  test: {
    environment: "jsdom",
    globals: true,
  },
});
