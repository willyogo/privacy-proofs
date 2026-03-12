import type { X509Certificate } from "@peculiar/x509";
import { derChildren, derOctetString, parseDer } from "./asn1";
import { toArrayBuffer, toHex, verifyEcdsaSignature } from "./crypto";

const SPDM_REQUEST_LENGTH = 37;
const SPDM_NONCE_LENGTH = 32;
const HOPPER_OR_BLACKWELL_SIGNATURE_LENGTH = 96;
const HOPPER_FWID_OID = "2.23.133.5.4.1";
const BLACKWELL_FWID_OID = "2.23.133.5.4.1.1";
const FWID_LENGTH = 48;
const OPAQUE_FIELD_FWID = 20;
const OPAQUE_FIELD_VERSION = 34;

export type ParsedNvidiaEvidence = {
  arch?: string;
  evidenceFwid?: string;
  leafCertificateFwid?: string;
  opaqueDataVersion?: number;
  requestNonce: string;
  responseNonce: string;
  signature: Uint8Array;
  signedBytes: Uint8Array;
};

export function normalizeNvidiaArchitecture(value: string | undefined): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim().toUpperCase()
    : undefined;
}

export function parseNvidiaEvidence({
  arch,
  evidence,
  leafCertificate,
}: {
  arch?: string;
  evidence: Uint8Array;
  leafCertificate: X509Certificate;
}): ParsedNvidiaEvidence | undefined {
  if (evidence.length <= SPDM_REQUEST_LENGTH + HOPPER_OR_BLACKWELL_SIGNATURE_LENGTH) {
    return undefined;
  }

  const request = evidence.slice(0, SPDM_REQUEST_LENGTH);
  const signedBytes = evidence.slice(0, evidence.length - HOPPER_OR_BLACKWELL_SIGNATURE_LENGTH);
  const signature = evidence.slice(evidence.length - HOPPER_OR_BLACKWELL_SIGNATURE_LENGTH);
  const response = evidence.slice(SPDM_REQUEST_LENGTH);
  const parsedResponse = parseSpdmResponse(
    response,
    HOPPER_OR_BLACKWELL_SIGNATURE_LENGTH,
  );

  if (!parsedResponse) {
    return undefined;
  }

  return {
    arch: normalizeNvidiaArchitecture(arch),
    evidenceFwid: parsedResponse.fwid,
    leafCertificateFwid: extractLeafCertificateFwid(leafCertificate),
    opaqueDataVersion: parsedResponse.opaqueDataVersion,
    requestNonce: toHex(request.slice(4, 4 + SPDM_NONCE_LENGTH)),
    responseNonce: parsedResponse.responseNonce,
    signature,
    signedBytes,
  };
}

export async function verifyNvidiaEvidenceSignature({
  leafCertificate,
  signedBytes,
  signature,
}: {
  leafCertificate: X509Certificate;
  signedBytes: Uint8Array;
  signature: Uint8Array;
}): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    toArrayBuffer(new Uint8Array(leafCertificate.publicKey.rawData)),
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"],
  );

  return verifyEcdsaSignature({
    hash: "SHA-384",
    namedCurve: "P-384",
    payload: signedBytes,
    publicKey,
    signature,
    signatureFormat: "ieee-p1363",
  });
}

function parseSpdmResponse(
  response: Uint8Array,
  signatureLength: number,
): { fwid?: string; opaqueDataVersion?: number; responseNonce: string } | undefined {
  let offset = 0;

  if (response.length < 4 + 1 + 3 + SPDM_NONCE_LENGTH + 2 + signatureLength) {
    return undefined;
  }

  offset += 4; // version, response code, param1, param2

  const blockCount = response[offset];
  offset += 1;
  if ((blockCount ?? 0) === 0) {
    return undefined;
  }

  const measurementRecordLength = readUint24LE(response, offset);
  offset += 3;
  if (measurementRecordLength === undefined || offset + measurementRecordLength > response.length) {
    return undefined;
  }

  offset += measurementRecordLength;

  const responseNonce = toHex(response.slice(offset, offset + SPDM_NONCE_LENGTH));
  offset += SPDM_NONCE_LENGTH;

  const opaqueLength = readUint16LE(response, offset);
  offset += 2;
  if (opaqueLength === undefined || offset + opaqueLength + signatureLength !== response.length) {
    return undefined;
  }

  const opaqueData = response.slice(offset, offset + opaqueLength);
  const opaqueFields = parseOpaqueFields(opaqueData);
  const fwid = opaqueFields.get(OPAQUE_FIELD_FWID)?.[0];
  const opaqueDataVersion = opaqueFields.get(OPAQUE_FIELD_VERSION)?.[0];

  return {
    fwid: fwid ? toHex(fwid) : undefined,
    opaqueDataVersion: opaqueDataVersion
      ? littleEndianBytesToNumber(opaqueDataVersion)
      : undefined,
    responseNonce,
  };
}

function parseOpaqueFields(opaqueData: Uint8Array): Map<number, Uint8Array[]> {
  const result = new Map<number, Uint8Array[]>();
  let offset = 0;

  while (offset + 4 <= opaqueData.length) {
    const type = readUint16LE(opaqueData, offset);
    const length = readUint16LE(opaqueData, offset + 2);
    offset += 4;

    if (type === undefined || length === undefined || offset + length > opaqueData.length) {
      return new Map();
    }

    const entry = opaqueData.slice(offset, offset + length);
    const existing = result.get(type) ?? [];
    existing.push(entry);
    result.set(type, existing);
    offset += length;
  }

  return offset === opaqueData.length ? result : new Map();
}

function extractLeafCertificateFwid(certificate: X509Certificate): string | undefined {
  const hopper = certificate.getExtension(HOPPER_FWID_OID);
  if (hopper) {
    const bytes = new Uint8Array(hopper.value);
    if (bytes.length >= FWID_LENGTH) {
      return toHex(bytes.slice(-FWID_LENGTH));
    }
  }

  const blackwell = certificate.getExtension(BLACKWELL_FWID_OID);
  if (!blackwell) {
    return undefined;
  }

  try {
    const extension = parseDer(new Uint8Array(blackwell.value));
    const children = derChildren(extension);
    const fwidList = children[6];
    const firstFwidEntry = fwidList ? derChildren(fwidList)[0] : undefined;
    const fwidNode = firstFwidEntry ? derChildren(firstFwidEntry)[1] : undefined;
    const fwidBytes = fwidNode ? derOctetString(fwidNode) : undefined;

    return fwidBytes && fwidBytes.length === FWID_LENGTH
      ? toHex(fwidBytes)
      : undefined;
  } catch {
    return undefined;
  }
}

function readUint16LE(bytes: Uint8Array, offset: number): number | undefined {
  if (offset + 2 > bytes.length) {
    return undefined;
  }

  return bytes[offset]! | (bytes[offset + 1]! << 8);
}

function readUint24LE(bytes: Uint8Array, offset: number): number | undefined {
  if (offset + 3 > bytes.length) {
    return undefined;
  }

  return (
    bytes[offset]! |
    (bytes[offset + 1]! << 8) |
    (bytes[offset + 2]! << 16)
  );
}

function littleEndianBytesToNumber(bytes: Uint8Array): number {
  return bytes.reduce(
    (total, byte, index) => total | (byte << (index * 8)),
    0,
  );
}
