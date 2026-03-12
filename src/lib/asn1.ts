import { concatBytes } from "./crypto";

export type DerNode = {
  children?: DerNode[];
  length: number;
  tag: number;
  value: Uint8Array;
};

export function parseDer(bytes: Uint8Array): DerNode {
  const { node, nextOffset } = parseDerAt(bytes, 0);

  if (nextOffset !== bytes.length) {
    throw new Error("Unexpected trailing bytes in DER payload.");
  }

  return node;
}

export function parseDerAt(
  bytes: Uint8Array,
  offset: number,
): { nextOffset: number; node: DerNode } {
  if (offset >= bytes.length) {
    throw new Error("Unexpected end of DER input.");
  }

  const tag = bytes[offset];
  const { length, nextOffset: valueOffset } = readDerLength(bytes, offset + 1);
  const endOffset = valueOffset + length;

  if (endOffset > bytes.length) {
    throw new Error("DER element length exceeds the available input.");
  }

  const value = bytes.slice(valueOffset, endOffset);
  const node: DerNode = {
    length,
    tag,
    value,
  };

  if (isConstructedTag(tag)) {
    node.children = parseChildren(value);
  }

  return {
    nextOffset: endOffset,
    node,
  };
}

export function derChildren(node: DerNode): DerNode[] {
  if (!isConstructedTag(node.tag)) {
    return [];
  }

  return node.children ?? [];
}

export function derOidToString(value: Uint8Array): string {
  if (value.length === 0) {
    throw new Error("DER OID is empty.");
  }

  const first = value[0];
  const parts = [Math.floor(first / 40), first % 40];
  let current = 0;

  for (let index = 1; index < value.length; index += 1) {
    current = (current << 7) | (value[index] & 0x7f);

    if ((value[index] & 0x80) === 0) {
      parts.push(current);
      current = 0;
    }
  }

  if (current !== 0) {
    throw new Error("DER OID ended mid-component.");
  }

  return parts.join(".");
}

export function derIntegerToNumber(node: DerNode): number {
  if (node.tag !== 0x02) {
    throw new Error("Expected a DER INTEGER.");
  }

  let result = 0;
  for (const byte of node.value) {
    result = (result << 8) | byte;
  }

  return result;
}

export function derIntegerToBigInt(node: DerNode): bigint {
  if (node.tag !== 0x02) {
    throw new Error("Expected a DER INTEGER.");
  }

  let result = 0n;
  for (const byte of node.value) {
    result = (result << 8n) | BigInt(byte);
  }

  return result;
}

export function derOctetString(node: DerNode): Uint8Array {
  if (node.tag !== 0x04) {
    throw new Error("Expected a DER OCTET STRING.");
  }

  return node.value;
}

export function derBitStringBytes(node: DerNode): Uint8Array {
  if (node.tag !== 0x03 || node.value.length === 0) {
    throw new Error("Expected a DER BIT STRING.");
  }

  return node.value.slice(1);
}

export function derOidValueMap(node: DerNode): Map<string, DerNode> {
  const result = new Map<string, DerNode>();

  for (const child of derChildren(node)) {
    const parts = derChildren(child);
    if (parts.length < 2 || parts[0]?.tag !== 0x06) {
      continue;
    }

    result.set(derOidToString(parts[0].value), parts[1]);
  }

  return result;
}

export function derContextChildren(node: DerNode, contextIndex: number): DerNode[] {
  const expectedTag = 0xa0 + contextIndex;
  if (node.tag !== expectedTag) {
    return [];
  }

  return derChildren(node);
}

export function concatenateDerChildren(node: DerNode): Uint8Array {
  return concatBytes(...derChildren(node).map((child) => serializeDer(child)));
}

export function serializeDer(node: DerNode): Uint8Array {
  return concatBytes(
    Uint8Array.of(node.tag),
    encodeDerLength(node.length),
    node.value,
  );
}

function parseChildren(bytes: Uint8Array): DerNode[] {
  const children: DerNode[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    const parsed = parseDerAt(bytes, offset);
    children.push(parsed.node);
    offset = parsed.nextOffset;
  }

  return children;
}

function isConstructedTag(tag: number): boolean {
  return (tag & 0x20) === 0x20;
}

function readDerLength(
  bytes: Uint8Array,
  offset: number,
): { length: number; nextOffset: number } {
  if (offset >= bytes.length) {
    throw new Error("Unexpected end of DER length.");
  }

  const first = bytes[offset];
  if ((first & 0x80) === 0) {
    return {
      length: first,
      nextOffset: offset + 1,
    };
  }

  const octetCount = first & 0x7f;
  if (octetCount === 0 || octetCount > 4 || offset + 1 + octetCount > bytes.length) {
    throw new Error("Unsupported DER length encoding.");
  }

  let length = 0;
  for (let index = 0; index < octetCount; index += 1) {
    length = (length << 8) | bytes[offset + 1 + index]!;
  }

  return {
    length,
    nextOffset: offset + 1 + octetCount,
  };
}

function encodeDerLength(length: number): Uint8Array {
  if (length < 0x80) {
    return Uint8Array.of(length);
  }

  const bytes: number[] = [];
  let remaining = length;

  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }

  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}
