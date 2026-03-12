import { sha256, sha384 } from "@noble/hashes/sha2.js";

export function sha256Hex(value: Uint8Array): string {
  return toHex(sha256(value));
}

export function sha384Hex(value: Uint8Array): string {
  return toHex(sha384(value));
}

export function sha256Bytes(value: Uint8Array): Uint8Array {
  return sha256(value);
}

export function sha384Bytes(value: Uint8Array): Uint8Array {
  return sha384(value);
}

export function toHex(value: Uint8Array): string {
  return Array.from(value)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function utf8ToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function concatBytes(...values: Uint8Array[]): Uint8Array {
  const length = values.reduce((total, value) => total + value.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;

  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }

  return result;
}

export function toBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength,
  ) as ArrayBuffer;
}

export function trimLeadingZeroBytes(value: Uint8Array): Uint8Array {
  let index = 0;

  while (index < value.length - 1 && value[index] === 0) {
    index += 1;
  }

  return value.slice(index);
}

function derEncodeLength(length: number): Uint8Array {
  if (length < 0x80) {
    return Uint8Array.of(length);
  }

  const octets: number[] = [];
  let remaining = length;

  while (remaining > 0) {
    octets.unshift(remaining & 0xff);
    remaining >>= 8;
  }

  return Uint8Array.of(0x80 | octets.length, ...octets);
}

function derEncodeInteger(value: Uint8Array): Uint8Array {
  const trimmed = trimLeadingZeroBytes(value);
  const needsPadding = (trimmed[0] ?? 0) >= 0x80;
  const body = needsPadding
    ? concatBytes(Uint8Array.of(0), trimmed)
    : trimmed;

  return concatBytes(Uint8Array.of(0x02), derEncodeLength(body.length), body);
}

export function p1363ToDerSignature(signature: Uint8Array): Uint8Array {
  if (signature.length === 0 || signature.length % 2 !== 0) {
    throw new Error("ECDSA P1363 signatures must contain equally sized R and S components.");
  }

  const componentLength = signature.length / 2;
  const r = signature.slice(0, componentLength);
  const s = signature.slice(componentLength);
  const rDer = derEncodeInteger(r);
  const sDer = derEncodeInteger(s);
  const body = concatBytes(rDer, sDer);

  return concatBytes(Uint8Array.of(0x30), derEncodeLength(body.length), body);
}

export async function verifyEcdsaSignature({
  hash,
  namedCurve,
  payload,
  publicKey,
  signature,
  signatureFormat = "der",
}: {
  hash: "SHA-256" | "SHA-384";
  namedCurve: "P-256" | "P-384";
  payload: Uint8Array;
  publicKey: CryptoKey | Uint8Array;
  signature: Uint8Array;
  signatureFormat?: "der" | "ieee-p1363";
}): Promise<boolean> {
  try {
    const cryptoKey =
      publicKey instanceof Uint8Array
        ? await crypto.subtle.importKey(
            "raw",
            toArrayBuffer(concatBytes(Uint8Array.of(4), publicKey)),
            { name: "ECDSA", namedCurve },
            false,
            ["verify"],
          )
        : publicKey;

    return await crypto.subtle.verify(
      { name: "ECDSA", hash },
      cryptoKey,
      toArrayBuffer(signature),
      toArrayBuffer(payload),
    );
  } catch {
    return false;
  }
}
