import {
  defineConfig,
  type Connect,
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

function intelCollateralProxyPlugin(): Plugin {
  const handleRequest: Connect.NextHandleFunction = async (req, res, next) => {
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
  req: Connect.IncomingMessage,
): Promise<ArrayBuffer | undefined> {
  const chunks: Uint8Array[] = [];

  for await (const chunk of req) {
    chunks.push(
      typeof chunk === "string"
        ? new TextEncoder().encode(chunk)
        : chunk instanceof Uint8Array
          ? chunk
          : new Uint8Array(chunk),
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
