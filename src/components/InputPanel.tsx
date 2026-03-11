import JsonDropzone from "./JsonDropzone";

type InputPanelProps = {
  collateralFileName?: string;
  collateralInput: string;
  fileName?: string;
  isVerifying: boolean;
  onCollateralInputChange: (nextValue: string, fileName?: string) => void;
  onInputChange: (nextValue: string, fileName?: string) => void;
  onVerify: () => void;
  rawInput: string;
};

export default function InputPanel({
  collateralFileName,
  collateralInput,
  fileName,
  isVerifying,
  onCollateralInputChange,
  onInputChange,
  onVerify,
  rawInput,
}: InputPanelProps) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="panel-kicker">Input</p>
          <h2>Load a report and verify</h2>
        </div>
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
        spellCheck={false}
        value={rawInput}
      />

      <JsonDropzone
        helperText="or click to choose an optional collateral bundle from disk"
        kicker="Collateral"
        onFileLoaded={onCollateralInputChange}
        title="Drop a collateral JSON bundle here"
      />

      <label
        className="textarea-label"
        htmlFor="collateral-json"
      >
        Optional collateral bundle JSON
      </label>
      <textarea
        id="collateral-json"
        className="json-textarea json-textarea-compact"
        onChange={(event) => onCollateralInputChange(event.target.value)}
        placeholder="Paste optional collateral JSON here"
        spellCheck={false}
        value={collateralInput}
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
          <span>
            {collateralFileName
              ? `Collateral: ${collateralFileName}`
              : "Collateral: none"}
          </span>
        </div>
      </div>

      <p className="panel-note">
        The current engine performs typed normalization, local bindings,
        certificate-chain validation, Intel quote signature checks, and
        advisory inspection of embedded claims. Missing collateral or
        unsupported raw-evidence formats keep the result in a partial state
        instead of upgrading it to verified.
      </p>
    </section>
  );
}
