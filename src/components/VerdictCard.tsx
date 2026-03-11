import type { ParseResult } from "../lib/types";

type VerdictCardProps = {
  fileName?: string;
  result: ParseResult;
};

const toneByStatus = {
  idle: "neutral",
  verified: "success",
  "partially-verified": "warning",
  invalid: "danger",
} as const;

export default function VerdictCard({ fileName, result }: VerdictCardProps) {
  const tone = toneByStatus[result.verification.status];

  return (
    <section className={`panel verdict-card verdict-${tone}`}>
      <div className="verdict-row">
        <span className="status-pill">{result.verification.badge}</span>
        <span className="milestone-pill">{result.verification.engineLabel}</span>
      </div>

      <div className="verdict-copy">
        <h2>{result.verification.headline}</h2>
        <p>{result.verification.description}</p>
      </div>

      <dl className="summary-grid">
        <div>
          <dt>Source</dt>
          <dd>{fileName ?? "Pasted text"}</dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd>{result.summary?.model ?? "Unavailable"}</dd>
        </div>
        <div>
          <dt>TEE</dt>
          <dd>{result.summary?.teeHardware ?? "Unavailable"}</dd>
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
          <dt>Events</dt>
          <dd>
            {result.summary?.eventLogCount !== undefined
              ? String(result.summary.eventLogCount)
              : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt>Verified at</dt>
          <dd>{result.summary?.verifiedAt ?? "Not embedded"}</dd>
        </div>
      </dl>
    </section>
  );
}
