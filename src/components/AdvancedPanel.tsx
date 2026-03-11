import type { ParseResult } from "../lib/types";

type AdvancedPanelProps = {
  result: ParseResult;
};

export default function AdvancedPanel({ result }: AdvancedPanelProps) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="panel-kicker">Advanced</p>
          <h2>Decoded overview</h2>
        </div>
      </div>

      {result.summary ? (
        <>
          <dl className="advanced-grid">
            <div>
              <dt>Top-level keys</dt>
              <dd>{result.summary.topLevelKeys.join(", ")}</dd>
            </div>
            <div>
              <dt>App name</dt>
              <dd>{result.summary.appName ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Compose hash</dt>
              <dd>{result.summary.composeHash ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Signing address</dt>
              <dd>{result.summary.signingAddress ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Derived address</dt>
              <dd>{result.summary.derivedSigningAddress ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>NVIDIA evidence entries</dt>
              <dd>
                {result.summary.nvidiaEvidenceCount !== undefined
                  ? String(result.summary.nvidiaEvidenceCount)
                  : "Unavailable"}
              </dd>
            </div>
            <div>
              <dt>Named events</dt>
              <dd>
                {result.summary.eventNames.length > 0
                  ? result.summary.eventNames.join(", ")
                  : "No named events"}
              </dd>
            </div>
            <div>
              <dt>Quote report data</dt>
              <dd>{result.summary.quoteReportData ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Embedded verified at</dt>
              <dd>{result.summary.verifiedAt ?? "Unavailable"}</dd>
            </div>
          </dl>

          <details className="advanced-details">
            <summary>Raw metadata preview</summary>
            <pre className="preview-block">
              {JSON.stringify(result.summary.preview, null, 2)}
            </pre>
          </details>
        </>
      ) : (
        <p className="empty-state">
          Metadata and decoded report structure will appear here once a report is
          loaded.
        </p>
      )}
    </section>
  );
}
