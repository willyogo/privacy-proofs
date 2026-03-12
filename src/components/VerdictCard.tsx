import type { ParseResult } from "../lib/types";

type VerdictCardProps = {
  className?: string;
  fileName?: string;
  result: ParseResult;
};

const toneByStatus = {
  idle: "neutral",
  verified: "success",
  "partially-verified": "warning",
  invalid: "danger",
} as const;

export default function VerdictCard({
  className,
  fileName,
  result,
}: VerdictCardProps) {
  const tone = toneByStatus[result.verification.status];
  const summary = result.summary;
  const shouldShowSummary = summary !== undefined;
  const formattedVerifiedAt = formatVerifiedAt(summary?.verifiedAt);

  return (
    <section
      className={`panel verdict-card verdict-${tone}${shouldShowSummary ? " verdict-expanded" : " verdict-collapsed"}${className ? ` ${className}` : ""}`}
    >
      <div className="verdict-row">
        <span className="status-pill">{result.verification.badge}</span>
        <span className="milestone-pill">{result.verification.engineLabel}</span>
      </div>

      <div className="verdict-copy">
        <h2>{result.verification.headline}</h2>
        <p>{result.verification.description}</p>
      </div>

      {shouldShowSummary ? (
        <dl className="summary-grid">
          <div>
            <dt>Source</dt>
            <dd>{fileName ?? "Pasted text"}</dd>
          </div>
          <div>
            <dt>Model</dt>
            <dd>{summary.model ?? "Unavailable"}</dd>
          </div>
          <div>
            <dt>TEE</dt>
            <dd>{summary.teeHardware ?? "Unavailable"}</dd>
          </div>
          <div>
            <dt>Checks passed</dt>
            <dd>
              {result.verification.supportedChecks > 0
                ? `${result.verification.passedChecks} / ${result.verification.supportedChecks}`
                : "Unavailable"}
            </dd>
          </div>
          <div>
            <dt>Mode</dt>
            <dd>{result.verification.mode}</dd>
          </div>
          <div>
            <dt>Crypto</dt>
            <dd>{result.verification.cryptographicStatus}</dd>
          </div>
          <div>
            <dt>Verification timestamp</dt>
            <dd>{formattedVerifiedAt}</dd>
          </div>
        </dl>
      ) : null}
    </section>
  );
}

function formatVerifiedAt(value?: string): string {
  if (!value) {
    return "Unavailable";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-US", {
    day: "numeric",
    hour: "numeric",
    hour12: true,
    minute: "2-digit",
    month: "short",
    second: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
    year: "numeric",
  }).format(parsed);
}
