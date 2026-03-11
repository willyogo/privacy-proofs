import { sha256 } from "@noble/hashes/sha2.js";

export function sha256Hex(value: Uint8Array): string {
  return toHex(sha256(value));
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
