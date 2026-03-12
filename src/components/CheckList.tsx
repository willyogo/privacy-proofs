import { useEffect, useId, useRef, useState } from "react";
import type { CheckDetail, CheckResult } from "../lib/check-result";
import { resolveJsonPath } from "../lib/json-path";
import type { ParseResult, VerificationSummary } from "../lib/types";

const INLINE_PREVIEW_LIMIT = 160;
const STRING_PREVIEW_LIMIT = 320;
const STRUCTURED_PREVIEW_LIMIT = 6000;

type RawValuePreview = {
  copyValue?: string;
  note?: string;
  preview: string;
};

type CheckListProps = {
  checks: CheckResult[];
  className?: string;
  report?: ParseResult["normalizedReport"];
  verification: VerificationSummary;
};

export default function CheckList({
  checks,
  className,
  report,
  verification,
}: CheckListProps) {
  const [openCheckKey, setOpenCheckKey] = useState<string | null>(null);
  const listId = useId();
  const tileRefs = useRef(new Map<string, HTMLLIElement>());
  const summaryText =
    verification.supportedChecks > 0
      ? `${verification.passedChecks}/${verification.supportedChecks} passed`
      : "No checks yet";

  useEffect(() => {
    if (!openCheckKey) {
      return;
    }

    if (!checks.some((check, index) => buildCheckKey(check, index) === openCheckKey)) {
      setOpenCheckKey(null);
    }
  }, [checks, openCheckKey]);

  useEffect(() => {
    if (!openCheckKey) {
      return;
    }

    const activeCheckKey = openCheckKey;

    function handleMouseDown(event: MouseEvent) {
      const target = event.target;
      if (!(target instanceof Node)) {
        return;
      }

      const tile = tileRefs.current.get(activeCheckKey);
      if (tile?.contains(target)) {
        return;
      }

      setOpenCheckKey(null);
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpenCheckKey(null);
      }
    }

    document.addEventListener("mousedown", handleMouseDown);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("mousedown", handleMouseDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [openCheckKey]);

  return (
    <section className={className ? `panel ${className}` : "panel"}>
      <div className="panel-header">
        <h2>Current Checks</h2>
        <span className={`panel-chip panel-chip-${verification.status}`}>
          {summaryText}
        </span>
      </div>

      {checks.length === 0 ? (
        <p className="empty-state">
          Load a report to see the verification engine results.
        </p>
      ) : (
        <ul className="check-grid">
          {checks.map((check, index) => {
            const checkKey = buildCheckKey(check, index);
            const isOpen = openCheckKey === checkKey;
            const popoverId = `${listId}-${index}`;
            const rawValue = describeResolvedValue(report, check.jsonPath);

            return (
              <li
                key={checkKey}
                className={`check-tile check-${check.status}${isOpen ? " check-tile-open" : ""}`}
                ref={(element) => {
                  if (element) {
                    tileRefs.current.set(checkKey, element);
                    return;
                  }

                  tileRefs.current.delete(checkKey);
                }}
              >
                <button
                  aria-controls={popoverId}
                  aria-expanded={isOpen}
                  aria-haspopup="dialog"
                  aria-label={`${statusLabel(check.status)}. ${check.label}. ${check.description}`}
                  className="check-tile-button"
                  onClick={() => {
                    setOpenCheckKey((current) => current === checkKey ? null : checkKey);
                  }}
                  type="button"
                >
                  <span className="check-tile-main">
                    <span
                      aria-hidden="true"
                      className={`check-glyph check-glyph-${check.status}`}
                    >
                      {statusGlyph(check.status)}
                    </span>
                    <span className="check-copy">
                      <span className="check-title">{check.label}</span>
                    </span>
                  </span>
                </button>

                {isOpen ? (
                  <div
                    aria-label={`${check.label} details`}
                    aria-modal="false"
                    className="check-popover"
                    id={popoverId}
                    role="dialog"
                  >
                    <div className="check-popover-header">
                      <div>
                        <p className="check-tooltip-title">{check.label}</p>
                        <p className="check-tooltip-description">
                          {check.description}
                        </p>
                      </div>
                      <span className={`check-status-pill check-status-${check.status}`}>
                        {statusLabel(check.status)}
                      </span>
                    </div>

                    <div className="check-popover-meta">
                      <span className="check-popover-chip">
                        {sourceLabel(check.source)}
                      </span>
                      <span className="check-popover-chip">
                        {domainLabel(check.domain)}
                      </span>
                      <span className="check-popover-chip">
                        {severityLabel(check.severity)}
                      </span>
                    </div>

                    {check.details && check.details.length > 0 ? (
                      <dl className="check-detail-list">
                        {check.details.map((detail, detailIndex) => {
                          const copyValue = getDetailCopyValue(detail);

                          return (
                            <div
                              className="check-detail-item"
                              key={`${checkKey}-detail-${detailIndex}`}
                            >
                              <dt>{detail.label}</dt>
                              <dd>{formatInlineValue(detail.value)}</dd>
                              {copyValue ? (
                                <button
                                  className="check-copy-button check-copy-button-inline"
                                  onClick={() => {
                                    void copyText(copyValue);
                                  }}
                                  type="button"
                                >
                                  Copy
                                </button>
                              ) : null}
                            </div>
                          );
                        })}
                      </dl>
                    ) : null}

                    <div className="check-popover-section">
                      <div className="check-popover-section-header">
                        <div>
                          <p className="check-popover-label">Verified path</p>
                          <code className="check-tooltip-path">{check.jsonPath}</code>
                        </div>
                        <button
                          className="check-copy-button"
                          onClick={() => {
                            void copyText(check.jsonPath);
                          }}
                          type="button"
                        >
                          Copy path
                        </button>
                      </div>

                      <div className="check-popover-section-header check-popover-section-header-tight">
                        <p className="check-popover-label">Raw value</p>
                        <button
                          className="check-copy-button"
                          disabled={!rawValue.copyValue}
                          onClick={() => {
                            if (rawValue.copyValue) {
                              void copyText(rawValue.copyValue);
                            }
                          }}
                          type="button"
                        >
                          Copy value
                        </button>
                      </div>

                      <pre className="check-raw-preview">{rawValue.preview}</pre>
                      {rawValue.note ? (
                        <p className="check-raw-note">{rawValue.note}</p>
                      ) : null}
                    </div>
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function buildCheckKey(check: CheckResult, index: number): string {
  return `${check.id}-${index}`;
}

function describeResolvedValue(
  report: ParseResult["normalizedReport"],
  jsonPath: string,
): RawValuePreview {
  if (!report) {
    return {
      preview:
        "Raw data is unavailable because this check was produced before the report normalized.",
    };
  }

  const resolved = resolveJsonPath(report, jsonPath);
  if (!resolved.found) {
    return {
      preview: "No value resolved at this path in the normalized report.",
    };
  }

  if (typeof resolved.value === "string") {
    const preview = buildTextPreview(resolved.value, STRING_PREVIEW_LIMIT);
    return {
      copyValue: resolved.value,
      note: preview.note,
      preview: preview.text,
    };
  }

  if (
    typeof resolved.value === "number" ||
    typeof resolved.value === "boolean" ||
    resolved.value === null
  ) {
    return {
      copyValue: JSON.stringify(resolved.value),
      preview: JSON.stringify(resolved.value),
    };
  }

  const serialized = JSON.stringify(resolved.value, null, 2);
  if (serialized === undefined) {
    return {
      preview: String(resolved.value),
    };
  }

  const preview = buildTextPreview(serialized, STRUCTURED_PREVIEW_LIMIT);
  return {
    copyValue: serialized,
    note: preview.note,
    preview: preview.text,
  };
}

function buildTextPreview(
  value: string,
  maxLength: number,
): {
  note?: string;
  text: string;
} {
  if (value.length === 0) {
    return {
      text: '""',
    };
  }

  if (value.length <= maxLength) {
    return {
      text: value,
    };
  }

  const headLength = Math.max(80, Math.floor(maxLength * 0.62));
  const tailLength = Math.max(48, maxLength - headLength);

  return {
    note: `Showing an excerpt of ${value.length.toLocaleString("en-US")} characters.`,
    text: `${value.slice(0, headLength)}\n...\n${value.slice(-tailLength)}`,
  };
}

function formatInlineValue(value: string): string {
  return buildTextPreview(value, INLINE_PREVIEW_LIMIT).text;
}

function getDetailCopyValue(detail: CheckDetail): string | undefined {
  if (detail.copyValue !== undefined) {
    return detail.copyValue;
  }

  if (detail.value === "Unavailable") {
    return undefined;
  }

  return detail.value;
}

function domainLabel(domain: CheckResult["domain"]): string {
  if (domain === "tdx") {
    return "TDX";
  }

  if (domain === "nvidia") {
    return "NVIDIA";
  }

  if (domain === "app-cert") {
    return "App certificate";
  }

  if (domain === "event-log") {
    return "Event log";
  }

  return capitalize(domain);
}

function severityLabel(severity: CheckResult["severity"]): string {
  return capitalize(severity);
}

function sourceLabel(source: CheckResult["source"]): string {
  return source === "embedded" ? "Embedded claim" : "Local check";
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function statusLabel(status: CheckResult["status"]) {
  if (status === "pass") {
    return "Passed";
  }

  if (status === "fail") {
    return "Failed";
  }

  return "Info";
}

function statusGlyph(status: CheckResult["status"]) {
  if (status === "pass") {
    return "✓";
  }

  if (status === "fail") {
    return "!";
  }

  return "i";
}

async function copyText(value: string) {
  await navigator.clipboard?.writeText(value);
}
