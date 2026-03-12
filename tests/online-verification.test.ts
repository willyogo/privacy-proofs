import { describe, expect, it } from "vitest";
import { validateCertificateChain } from "../src/lib/certificates";
import { parseIntelPckExtensions, parseQeReport } from "../src/lib/intel";
import {
  completeIntelOnlineVerification,
  completeNvidiaOnlineVerification,
} from "../src/lib/online-verification";
import { decodeTdxQuote } from "../src/lib/verifier";
import {
  INTEL_TDX_QE_IDENTITY,
  INTEL_TDX_QUOTE_HEX,
  INTEL_TDX_TCB_INFO,
  INTEL_TDX_TCB_SIGN_CHAIN,
} from "./fixtures/intelVendor";

describe("online verification", () => {
  it("routes Intel collateral fetches through the configured proxy URL", async () => {
    const quote = decodeTdxQuote(INTEL_TDX_QUOTE_HEX)!;
    const pckValidation = await validateCertificateChain({
      bundle: quote.certificationData!,
      bundleLabel: "Intel PCK certificate chain",
      domain: "intel",
      jsonPath: "$.intel_quote",
    });
    const pckExtensions = parseIntelPckExtensions(pckValidation.chain![0]!);
    const qeReport = parseQeReport(quote.qeReport!);
    const requestedUrls: string[] = [];

    const result = await completeIntelOnlineVerification({
      options: {
        fetchImpl: async (input) => {
          const url = String(input);
          requestedUrls.push(url);

          if (
            url.includes(
              encodeURIComponent(
                "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
              ),
            )
          ) {
            return new Response(JSON.stringify(INTEL_TDX_QE_IDENTITY), {
              headers: {
                "content-type": "application/json",
                "SGX-Enclave-Identity-Issuer-Chain": encodeURIComponent(
                  INTEL_TDX_TCB_SIGN_CHAIN,
                ),
              },
              status: 200,
            });
          }

          if (
            url.includes(
              encodeURIComponent(
                `https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=${pckExtensions!.fmspc}&update=standard`,
              ),
            )
          ) {
            return new Response(JSON.stringify(INTEL_TDX_TCB_INFO), {
              headers: {
                "content-type": "application/json",
                "TCB-Info-Issuer-Chain": encodeURIComponent(
                  INTEL_TDX_TCB_SIGN_CHAIN,
                ),
              },
              status: 200,
            });
          }

          if (
            url.includes(
              encodeURIComponent(
                "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=pem",
              ),
            )
          ) {
            return new Response(
              "-----BEGIN X509 CRL-----\nAQ==\n-----END X509 CRL-----\n",
              {
                headers: {
                  "content-type": "application/x-pem-file",
                  "SGX-PCK-CRL-Issuer-Chain": encodeURIComponent(
                    quote.certificationData!,
                  ),
                },
                status: 200,
              },
            );
          }

          return new Response(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]), {
            headers: {
              "content-type": "application/pkix-crl",
            },
            status: 200,
          });
        },
        intelBaseUrl: "/api/intel-proxy",
      },
      pckChain: pckValidation.chain!,
      pckExtensions: pckExtensions!,
      qeReport: qeReport!,
      quoteMrSignerSeam: quote.mrSignerSeam,
      quoteSeamAttributes: quote.seamAttributes,
      quoteTeeTcbSvn: quote.teeTcbSvn,
    });

    expect(result.status).toBe("partial");
    expect(requestedUrls.length).toBeGreaterThanOrEqual(3);
    expect(
      requestedUrls.every((url) => url.startsWith("/api/intel-proxy?url=")),
    ).toBe(true);
  });

  it("accepts nvapi keys without the Bearer prefix and verifies NRAS JWTs", async () => {
    const apiKey = "nvapi-fixture-key";
    const nonce = "aa".repeat(32);
    const jwkKid = "fixture-key";
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"],
    );
    const exportedJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const publicJwk = Object.assign({}, exportedJwk, {
      alg: "ES256",
      kid: jwkKid,
      use: "sig",
    }) as JsonWebKey;
    const overallJwt = await signJwt({
      header: {
        alg: "ES256",
        kid: jwkKid,
        typ: "JWT",
      },
      payload: {
        eat_nonce: nonce,
        "x-nvidia-overall-att-result": true,
      },
      privateKey: keyPair.privateKey,
    });
    const deviceJwt = await signJwt({
      header: {
        alg: "ES256",
        kid: jwkKid,
        typ: "JWT",
      },
      payload: {
        eat_nonce: nonce,
        measres: "success",
        "x-nvidia-gpu-arch-check": true,
        "x-nvidia-gpu-attestation-report-cert-chain": {
          "x-nvidia-cert-status": {
            "x-nvidia-cert-chain-status": true,
          },
        },
        "x-nvidia-gpu-attestation-report-nonce-match": true,
        "x-nvidia-gpu-attestation-report-signature-verified": true,
      },
      privateKey: keyPair.privateKey,
    });
    const postHeaders: Array<{
      authorization: string | null;
      xApiKey: string | null;
    }> = [];

    const result = await completeNvidiaOnlineVerification({
      evidenceCount: 1,
      expectedArch: "HOPPER",
      expectedNonce: nonce,
      options: {
        fetchImpl: async (input, init) => {
          const url = String(input);

          if (url.endsWith("/attest/gpu")) {
            const headers = new Headers(init?.headers);
            postHeaders.push({
              authorization: headers.get("authorization"),
              xApiKey: headers.get("x-api-key"),
            });

            return new Response(
              JSON.stringify({
                detached_eat: [overallJwt, { gpu0: deviceJwt }],
              }),
              {
                headers: {
                  "content-type": "application/json",
                },
                status: 200,
              },
            );
          }

          if (url.endsWith("/jwks.json")) {
            return new Response(
              JSON.stringify({
                keys: [publicJwk],
              }),
              {
                headers: {
                  "content-type": "application/json",
                },
                status: 200,
              },
            );
          }

          throw new Error(`Unexpected URL ${url}`);
        },
        nvidiaApiKey: apiKey,
        nvidiaBaseUrl: "https://example.test/v4",
        nvidiaJwksUrl: "https://example.test/.well-known/jwks.json",
      },
      payload: {
        arch: "HOPPER",
        evidence_list: [
          {
            arch: "HOPPER",
            certificate: "fixture-certificate",
            evidence: "fixture-evidence",
          },
        ],
        nonce,
      },
    });

    expect(postHeaders).toEqual([
      {
        authorization: apiKey,
        xApiKey: null,
      },
    ]);
    expect(result.status).toBe("verified");
    expect(
      result.checks.find((check) => check.id === "nvidia-online-overall-signature")?.status,
    ).toBe("pass");
    expect(
      result.checks.find((check) => check.id === "nvidia-online-device-signature-0")?.status,
    ).toBe("pass");
  });
});

async function signJwt({
  header,
  payload,
  privateKey,
}: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  privateKey: CryptoKey;
}): Promise<string> {
  const encodedHeader = base64UrlEncodeJson(header);
  const encodedPayload = base64UrlEncodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const derSignature = new Uint8Array(
    await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: "SHA-256",
      },
      privateKey,
      new TextEncoder().encode(signingInput),
    ),
  );
  return `${signingInput}.${base64UrlEncode(derSignature)}`;
}

function base64UrlEncodeJson(value: Record<string, unknown>): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function base64UrlEncode(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
