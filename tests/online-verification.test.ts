import { describe, expect, it } from "vitest";
import { completeNvidiaOnlineVerification } from "../src/lib/online-verification";

describe("online verification", () => {
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
