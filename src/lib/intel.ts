import type { X509Certificate } from "@peculiar/x509";
import { derChildren, derIntegerToNumber, derOctetString, derOidValueMap, parseDer } from "./asn1";
import { toArrayBuffer, toHex, utf8ToBytes, verifyEcdsaSignature } from "./crypto";
import type {
  IntelQeIdentityLevel,
  IntelSignedQeIdentity,
  IntelSignedTcbInfo,
  IntelTcbLevel,
} from "./types";

const SGX_EXTENSION_OID = "1.2.840.113741.1.13.1";
const SGX_EXTENSION_PREFIX = `${SGX_EXTENSION_OID}.`;
const SGX_TCB_OID = `${SGX_EXTENSION_PREFIX}2`;
const SGX_PCE_ID_OID = `${SGX_EXTENSION_PREFIX}3`;
const SGX_FMSPC_OID = `${SGX_EXTENSION_PREFIX}4`;
const SGX_TCB_COMPONENT_BASE = `${SGX_TCB_OID}.`;
const SGX_TCB_PCE_SVN_OID = `${SGX_TCB_OID}.17`;
const SGX_TCB_CPU_SVN_OID = `${SGX_TCB_OID}.18`;

const QE_MISCSELECT_OFFSET = 16;
const QE_ATTRIBUTES_OFFSET = 48;
const QE_MRSIGNER_OFFSET = 128;
const QE_ISV_PROD_ID_OFFSET = 256;
const QE_ISV_SVN_OFFSET = 258;
const QE_REPORT_DATA_OFFSET = 320;

export type ParsedIntelPckExtensions = {
  cpuSvn: number[];
  fmspc: string;
  pceId: string;
  pceSvn: number;
};

export type ParsedQeReport = {
  attributes: string;
  isvprodid: number;
  isvsvn: number;
  miscselect: string;
  mrsigner: string;
  reportData: string;
};

export type IntelQeIdentityEvaluation = {
  acceptable: boolean;
  attributesMatch: boolean;
  isvprodidMatch: boolean;
  matchedLevel?: IntelQeIdentityLevel;
  miscselectMatch: boolean;
  mrsignerMatch: boolean;
  status?: string;
};

export type IntelTcbEvaluation = {
  acceptable: boolean;
  fmspcMatch: boolean;
  levelMatch: boolean;
  matchedLevel?: IntelTcbLevel;
  pceIdMatch: boolean;
  status?: string;
  tdxModuleAttributesMatch: boolean;
  tdxModuleMrsignerMatch: boolean;
};

export function parseIntelPckExtensions(
  certificate: X509Certificate,
): ParsedIntelPckExtensions | undefined {
  const extension = certificate.getExtension(SGX_EXTENSION_OID);
  if (!extension) {
    return undefined;
  }

  const root = parseDer(new Uint8Array(extension.value));
  const fields = derOidValueMap(root);
  const tcbNode = fields.get(SGX_TCB_OID);
  const fmspcNode = fields.get(SGX_FMSPC_OID);
  const pceIdNode = fields.get(SGX_PCE_ID_OID);

  if (!tcbNode || !fmspcNode || !pceIdNode) {
    return undefined;
  }

  const tcbFields = derOidValueMap(tcbNode);
  const cpuSvnNode = tcbFields.get(SGX_TCB_CPU_SVN_OID);
  const pceSvnNode = tcbFields.get(SGX_TCB_PCE_SVN_OID);

  if (!cpuSvnNode || !pceSvnNode) {
    return undefined;
  }

  const cpuSvn = Array.from(derOctetString(cpuSvnNode));
  if (cpuSvn.length !== 16) {
    return undefined;
  }

  return {
    cpuSvn,
    fmspc: toHex(derOctetString(fmspcNode)),
    pceId: toHex(derOctetString(pceIdNode)),
    pceSvn: derIntegerToNumber(pceSvnNode),
  };
}

export function parseQeReport(report: Uint8Array): ParsedQeReport | undefined {
  if (report.length < QE_REPORT_DATA_OFFSET + 64) {
    return undefined;
  }

  const view = new DataView(report.buffer, report.byteOffset, report.byteLength);

  return {
    attributes: toHex(report.slice(QE_ATTRIBUTES_OFFSET, QE_ATTRIBUTES_OFFSET + 16)),
    isvprodid: view.getUint16(QE_ISV_PROD_ID_OFFSET, true),
    isvsvn: view.getUint16(QE_ISV_SVN_OFFSET, true),
    miscselect: toHex(report.slice(QE_MISCSELECT_OFFSET, QE_MISCSELECT_OFFSET + 4)),
    mrsigner: toHex(report.slice(QE_MRSIGNER_OFFSET, QE_MRSIGNER_OFFSET + 32)),
    reportData: toHex(report.slice(QE_REPORT_DATA_OFFSET, QE_REPORT_DATA_OFFSET + 64)),
  };
}

export async function verifyIntelCollateralSignature({
  body,
  chain,
  signedBodyText,
  signatureHex,
}: {
  body: IntelSignedQeIdentity["enclaveIdentity"] | IntelSignedTcbInfo["tcbInfo"];
  chain: X509Certificate[];
  signedBodyText?: string;
  signatureHex: string;
}): Promise<boolean> {
  const signature = normalizeHex(signatureHex);
  if (!signature || !chain[0]) {
    return false;
  }

  const publicKey = await crypto.subtle.importKey(
    "spki",
    toArrayBuffer(new Uint8Array(chain[0].publicKey.rawData)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );

  return verifyEcdsaSignature({
    hash: "SHA-256",
    namedCurve: "P-256",
    payload: utf8ToBytes(signedBodyText ?? JSON.stringify(body)),
    publicKey,
    signature: hexToBytes(signature),
    signatureFormat: "ieee-p1363",
  });
}

export function extractIntelSignedBodyText(
  rawValue: unknown,
  key: "enclaveIdentity" | "tcbInfo",
): string | undefined {
  let container = rawValue;

  if (typeof container === "string") {
    try {
      container = JSON.parse(container);
    } catch {
      return undefined;
    }
  }

  if (!isRecord(container)) {
    return undefined;
  }

  const body = container[key];
  return body === undefined ? undefined : JSON.stringify(body);
}

export function evaluateQeIdentity({
  qeIdentity,
  qeReport,
}: {
  qeIdentity: IntelSignedQeIdentity["enclaveIdentity"];
  qeReport: ParsedQeReport;
}): IntelQeIdentityEvaluation {
  const miscselectMatch = maskedHexEquals(
    qeReport.miscselect,
    qeIdentity.miscselect,
    qeIdentity.miscselectMask,
  );
  const attributesMatch = maskedHexEquals(
    qeReport.attributes,
    qeIdentity.attributes,
    qeIdentity.attributesMask,
  );
  const mrsignerMatch =
    normalizeHex(qeReport.mrsigner) === normalizeHex(qeIdentity.mrsigner);
  const isvprodidMatch = qeReport.isvprodid === qeIdentity.isvprodid;
  const matchedLevel = [...qeIdentity.tcbLevels]
    .sort((left, right) => (right.tcb.isvsvn & 0xff) - (left.tcb.isvsvn & 0xff))
    .find((level) => (level.tcb.isvsvn & 0xff) <= qeReport.isvsvn);
  const status = matchedLevel?.tcbStatus;
  const acceptable = Boolean(
    miscselectMatch &&
      attributesMatch &&
      mrsignerMatch &&
      isvprodidMatch &&
      matchedLevel &&
      isIntelStatusAcceptable(status),
  );

  return {
    acceptable,
    attributesMatch,
    isvprodidMatch,
    matchedLevel,
    miscselectMatch,
    mrsignerMatch,
    status,
  };
}

export function evaluateTcbInfo({
  pckExtensions,
  quoteMrSignerSeam,
  quoteSeamAttributes,
  quoteTeeTcbSvn,
  tcbInfo,
}: {
  pckExtensions: ParsedIntelPckExtensions;
  quoteMrSignerSeam: string;
  quoteSeamAttributes: string;
  quoteTeeTcbSvn: number[];
  tcbInfo: IntelSignedTcbInfo["tcbInfo"];
}): IntelTcbEvaluation {
  const fmspcMatch =
    normalizeHex(pckExtensions.fmspc) === normalizeHex(tcbInfo.fmspc);
  const pceIdMatch =
    normalizeHex(pckExtensions.pceId) === normalizeHex(tcbInfo.pceId);
  const tdxModuleMrsignerMatch =
    !tcbInfo.tdxModule ||
    normalizeHex(quoteMrSignerSeam) === normalizeHex(tcbInfo.tdxModule.mrsigner);
  const tdxModuleAttributesMatch =
    !tcbInfo.tdxModule ||
    maskedHexEquals(
      quoteSeamAttributes,
      tcbInfo.tdxModule.attributes,
      tcbInfo.tdxModule.attributesMask,
    );

  const matchedLevel = [...tcbInfo.tcbLevels].find((level) =>
    matchesTcbLevel(level, pckExtensions, quoteTeeTcbSvn),
  );
  const status = matchedLevel?.tcbStatus;
  const acceptable = Boolean(
    fmspcMatch &&
      pceIdMatch &&
      tdxModuleMrsignerMatch &&
      tdxModuleAttributesMatch &&
      matchedLevel &&
      isIntelStatusAcceptable(status),
  );

  return {
    acceptable,
    fmspcMatch,
    levelMatch: matchedLevel !== undefined,
    matchedLevel,
    pceIdMatch,
    status,
    tdxModuleAttributesMatch,
    tdxModuleMrsignerMatch,
  };
}

export function isCollateralCurrent(
  body: Pick<IntelSignedQeIdentity["enclaveIdentity"], "issueDate" | "nextUpdate">,
  now = new Date(),
): boolean {
  const issueDate = Date.parse(body.issueDate);
  const nextUpdate = Date.parse(body.nextUpdate);

  return (
    Number.isFinite(issueDate) &&
    Number.isFinite(nextUpdate) &&
    issueDate <= now.getTime() &&
    nextUpdate >= now.getTime()
  );
}

export function isIntelStatusAcceptable(status?: string): boolean {
  return status === "UpToDate";
}

function matchesTcbLevel(
  level: IntelTcbLevel,
  pckExtensions: ParsedIntelPckExtensions,
  quoteTeeTcbSvn: number[],
): boolean {
  const sgxComponents = level.tcb.sgxtcbcomponents.map((component) => component.svn & 0xff);
  const tdxComponents = level.tcb.tdxtcbcomponents?.map(
    (component) => component.svn & 0xff,
  );

  return (
    componentsMatchOrExceed(pckExtensions.cpuSvn, sgxComponents) &&
    pckExtensions.pceSvn >= (level.tcb.pcesvn & 0xffff) &&
    (tdxComponents === undefined ||
      componentsMatchOrExceed(quoteTeeTcbSvn, tdxComponents))
  );
}

function componentsMatchOrExceed(actual: number[], expected: number[]): boolean {
  if (actual.length !== expected.length) {
    return false;
  }

  return expected.every((value, index) => (actual[index] ?? -1) >= value);
}

function maskedHexEquals(
  actualValue: string,
  expectedValue: string,
  maskValue: string,
): boolean {
  const actual = normalizeHex(actualValue);
  const expected = normalizeHex(expectedValue);
  const mask = normalizeHex(maskValue);

  if (!actual || !expected || !mask) {
    return false;
  }

  const actualBytes = hexToBytes(actual);
  const expectedBytes = hexToBytes(expected);
  const maskBytes = hexToBytes(mask);

  if (
    actualBytes.length !== expectedBytes.length ||
    actualBytes.length !== maskBytes.length
  ) {
    return false;
  }

  return actualBytes.every(
    (byte, index) => (byte & maskBytes[index]!) === (expectedBytes[index]! & maskBytes[index]!),
  );
}

function hexToBytes(value: string): Uint8Array {
  const normalized = value.trim().replace(/^0x/i, "");
  const bytes = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }

  return bytes;
}

function normalizeHex(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim().replace(/^0x/i, "");
  if (trimmed.length === 0 || trimmed.length % 2 !== 0) {
    return undefined;
  }

  return /^[0-9a-fA-F]+$/.test(trimmed) ? trimmed.toLowerCase() : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
