import type { CheckResult } from "../lib/check-result";
import type { VerificationSummary } from "../lib/types";

type CheckListProps = {
  checks: CheckResult[];
  className?: string;
  verification: VerificationSummary;
};

export default function CheckList({
  checks,
  className,
  verification,
}: CheckListProps) {
  const summaryText =
    verification.supportedChecks > 0
      ? `${verification.passedChecks}/${verification.supportedChecks} passed`
      : "No checks yet";

  return (
    <section className={className ? `panel ${className}` : "panel"}>
      <div className="panel-header">
        <div>
          <p className="panel-kicker">Diagnostics</p>
          <h2>Current Checks</h2>
        </div>
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
          {checks.map((check) => (
            <li
              key={check.id}
              aria-label={`${statusLabel(check.status)}. ${check.label}. ${check.description}. Path ${check.jsonPath}.`}
              className={`check-tile check-${check.status}`}
              tabIndex={0}
              title={`${statusLabel(check.status)}: ${check.description} (${check.jsonPath})`}
            >
              <div className="check-tile-main">
                <span className={`check-glyph check-glyph-${check.status}`}>
                  {statusGlyph(check.status)}
                </span>
                <div className="check-copy">
                  <span className="check-title">{check.label}</span>
                  <span className="check-meta">
                    {check.source} · {check.domain} · {check.severity}
                  </span>
                </div>
              </div>

              <div className="check-tooltip" role="tooltip">
                <div className="check-tooltip-header">
                  <p className="check-tooltip-title">{check.label}</p>
                  <span className={`check-status-pill check-status-${check.status}`}>
                    {statusLabel(check.status)}
                  </span>
                </div>
                <p className="check-tooltip-description">{check.description}</p>
                <p className="check-tooltip-meta">
                  {check.source} · {check.domain} · {check.severity}
                </p>
                <code className="check-tooltip-path">{check.jsonPath}</code>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
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
