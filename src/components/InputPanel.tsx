import JsonDropzone from "./JsonDropzone";

type InputPanelProps = {
  className?: string;
  fileName?: string;
  isVerifying: boolean;
  onInputChange: (nextValue: string, fileName?: string) => void;
  onVerify: () => void;
  rawInput: string;
};

export default function InputPanel({
  className,
  fileName,
  isVerifying,
  onInputChange,
  onVerify,
  rawInput,
}: InputPanelProps) {
  return (
    <section className={className ? `panel ${className}` : "panel"}>
      <div className="panel-header">
        <h2>Load a report and verify</h2>
        <span className="panel-chip">Frontend only</span>
      </div>

      <JsonDropzone
        helperText="or click to choose an attestation report from disk"
        kicker="Report"
        onFileLoaded={onInputChange}
        title="Drop a report JSON file here"
      />

      <label
        className="textarea-label"
        htmlFor="attestation-json"
      >
        Raw attestation JSON
      </label>
      <textarea
        id="attestation-json"
        className="json-textarea"
        onChange={(event) => onInputChange(event.target.value)}
        placeholder="Paste a Venice attestation report here"
        rows={2}
        spellCheck={false}
        value={rawInput}
      />

      <div className="input-actions">
        <button
          className="verify-button"
          disabled={isVerifying || rawInput.trim().length === 0}
          onClick={onVerify}
          type="button"
        >
          {isVerifying ? "Verifying…" : "Verify report"}
        </button>
        <div className="input-files">
          <span>{fileName ? `Report: ${fileName}` : "Report: pasted text"}</span>
        </div>
      </div>

      <p className="panel-note">
        The current engine performs typed normalization, local bindings,
        certificate-chain validation, Intel and NVIDIA cryptographic checks,
        and advisory inspection of embedded Venice or NRAS provenance already
        present in the raw report.
      </p>
    </section>
  );
}
