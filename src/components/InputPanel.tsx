import type { VerificationMode } from "../lib/types";
import JsonDropzone from "./JsonDropzone";

type InputPanelProps = {
  activeMode: VerificationMode | null;
  className?: string;
  fileName?: string;
  nvidiaApiKey: string;
  onInputChange: (nextValue: string, fileName?: string) => void;
  onNvidiaApiKeyChange: (nextValue: string) => void;
  onVerifyOffline: () => void;
  onVerifyOnline: () => void;
  rawInput: string;
  showNvidiaApiKeyInput: boolean;
};

export default function InputPanel({
  activeMode,
  className,
  fileName,
  nvidiaApiKey,
  onInputChange,
  onNvidiaApiKeyChange,
  onVerifyOffline,
  onVerifyOnline,
  rawInput,
  showNvidiaApiKeyInput,
}: InputPanelProps) {
  const isVerifying = activeMode !== null;

  return (
    <section className={className ? `panel ${className}` : "panel"}>
      <div className="panel-header">
        <h2>Load a report and verify</h2>
        <span className="panel-chip">Offline first</span>
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

      {showNvidiaApiKeyInput ? (
        <>
          <label
            className="textarea-label"
            htmlFor="nvidia-api-key"
          >
            <a
              href="https://build.nvidia.com/"
              rel="noreferrer noopener"
              target="_blank"
            >
              NVIDIA API key
            </a>{" "}
            (shown because NRAS rejected the unauthenticated request)
          </label>
          <input
            autoComplete="off"
            className="text-input"
            id="nvidia-api-key"
            onChange={(event) => onNvidiaApiKeyChange(event.target.value)}
            placeholder="Used only when live NVIDIA verification requires authentication"
            spellCheck={false}
            type="password"
            value={nvidiaApiKey}
          />
        </>
      ) : null}

      <div className="input-actions">
        <div className="input-actions-group">
          <button
            className="verify-button"
            disabled={isVerifying || rawInput.trim().length === 0}
            onClick={onVerifyOffline}
            type="button"
          >
            {activeMode === "offline" ? "Verifying…" : "Verify locally"}
          </button>
          <button
            className="verify-button verify-button-secondary"
            disabled={isVerifying || rawInput.trim().length === 0}
            onClick={onVerifyOnline}
            type="button"
          >
            {activeMode === "online" ? "Completing…" : "Complete full verification"}
          </button>
        </div>
        <div className="input-files">
          <span>{fileName ? `Report: ${fileName}` : "Report: pasted text"}</span>
        </div>
      </div>

      <p className="panel-note">
        Local verification runs typed normalization, local bindings, Intel quote
        cryptography, NVIDIA evidence verification, and advisory inspection of
        embedded provenance. Full verification adds live Intel PCS collateral
        checks plus NVIDIA NRAS confirmation, using only the Venice report as
        input. The app tries NVIDIA online verification anonymously first and
        only asks for an API key if NRAS returns unauthorized.
      </p>
    </section>
  );
}
