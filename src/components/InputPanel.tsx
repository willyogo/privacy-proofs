import JsonDropzone from "./JsonDropzone";

type InputPanelProps = {
  onInputChange: (nextValue: string, fileName?: string) => void;
  rawInput: string;
};

export default function InputPanel({
  onInputChange,
  rawInput,
}: InputPanelProps) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="panel-kicker">Input</p>
          <h2>Paste or upload a report</h2>
        </div>
        <span className="panel-chip">Frontend only</span>
      </div>

      <JsonDropzone onFileLoaded={onInputChange} />

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

      <p className="panel-note">
        The current engine verifies local bindings, decoded TDX quote fields,
        event log consistency, and any embedded TDX or NVIDIA verification
        claims present in the report.
      </p>
    </section>
  );
}
