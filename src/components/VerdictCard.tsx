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

  return (
    <section
      className={`panel verdict-card verdict-${tone}${className ? ` ${className}` : ""}`}
    >
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
          <dt>Mode</dt>
          <dd>{result.verification.mode}</dd>
        </div>
        <div>
          <dt>Crypto</dt>
          <dd>{result.verification.cryptographicStatus}</dd>
        </div>
        <div>
          <dt>Collateral</dt>
          <dd>{result.verification.collateralStatus}</dd>
        </div>
        <div>
          <dt>Verified at</dt>
          <dd>{result.summary?.verifiedAt ?? "Not embedded"}</dd>
        </div>
      </dl>
    </section>
  );
}
