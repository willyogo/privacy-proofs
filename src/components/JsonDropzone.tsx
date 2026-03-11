import { useId } from "react";

type JsonDropzoneProps = {
  helperText: string;
  kicker: string;
  onFileLoaded: (content: string, fileName?: string) => void;
  title: string;
};

export default function JsonDropzone({
  helperText,
  kicker,
  onFileLoaded,
  title,
}: JsonDropzoneProps) {
  const inputId = useId();

  async function readFile(file: File) {
    const content = await file.text();
    onFileLoaded(content, file.name);
  }

  return (
    <div className="dropzone-wrap">
      <label
        className="dropzone"
        htmlFor={inputId}
        onDragOver={(event) => event.preventDefault()}
        onDrop={async (event) => {
          event.preventDefault();
          const file = event.dataTransfer.files?.[0];
          if (file) {
            await readFile(file);
          }
        }}
      >
        <input
          id={inputId}
          accept=".json,application/json"
          className="dropzone-input"
          onChange={async (event) => {
            const file = event.target.files?.[0];
            if (file) {
              await readFile(file);
            }
          }}
          type="file"
        />
        <span className="dropzone-kicker">{kicker}</span>
        <strong>{title}</strong>
        <span>{helperText}</span>
      </label>
    </div>
  );
}
