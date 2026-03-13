import { concatBytes, sha384Hex } from "../../src/lib/crypto";
import type { EventLogEntry } from "../../src/lib/types";

const RTMR_LENGTH_BYTES = 48;
const RTMR_NAMES = ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] as const;

export function withSyntheticDigests(
  entries: EventLogEntry[],
  defaultImr = 3,
): EventLogEntry[] {
  return entries.map((entry, index) => {
    const imr = typeof entry.imr === "number" ? entry.imr : defaultImr;
    return {
      ...entry,
      digest: sha384Hex(
        new TextEncoder().encode(
          JSON.stringify({
            event: entry.event,
            event_payload: entry.event_payload,
            imr,
            index,
          }),
        ),
      ),
      imr,
    };
  });
}

export function replaySyntheticRtmrs(
  entries: EventLogEntry[],
): Record<(typeof RTMR_NAMES)[number], string> {
  const rtmrs = Object.fromEntries(
    RTMR_NAMES.map((name) => [name, "00".repeat(RTMR_LENGTH_BYTES)]),
  ) as Record<(typeof RTMR_NAMES)[number], string>;

  for (const entry of entries) {
    if (typeof entry.imr !== "number" || entry.imr < 0 || entry.imr > 3) {
      continue;
    }

    if (typeof entry.digest !== "string") {
      continue;
    }

    const rtmr = RTMR_NAMES[entry.imr];
    rtmrs[rtmr] = sha384Hex(
      concatBytes(hexToBytes(rtmrs[rtmr]), hexToBytes(entry.digest)),
    );
  }

  return rtmrs;
}

function hexToBytes(value: string): Uint8Array {
  const normalized = value.replace(/^0x/i, "");
  const bytes = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }

  return bytes;
}
