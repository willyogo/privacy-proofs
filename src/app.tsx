import { useState } from "react";
import AdvancedPanel from "./components/AdvancedPanel";
import CheckList from "./components/CheckList";
import InputPanel from "./components/InputPanel";
import VerdictCard from "./components/VerdictCard";
import { createIdleParseResult, parseReportSource } from "./lib/normalize";
import type { ParseResult } from "./lib/types";

export default function App() {
  const [rawInput, setRawInput] = useState("");
  const [fileName, setFileName] = useState<string | undefined>(undefined);
  const [result, setResult] = useState<ParseResult>(createIdleParseResult());

  function handleInputChange(nextValue: string, nextFileName?: string) {
    setRawInput(nextValue);
    setFileName(nextFileName);
    setResult(parseReportSource(nextValue, nextFileName));
  }

  return (
    <div className="page-shell">
      <div className="page-overlay" />
      <header className="page-header">
        <div className="brand">
          <img
            alt="Venice logo"
            className="brand-logo"
            src="/venice-logotype.svg"
          />
          <div>
            <p className="eyebrow">Browser verifier</p>
            <h1>Venice Attestation Verifier</h1>
          </div>
        </div>
        <p className="hero-copy">
          Paste or upload a Venice attestation report to run browser-side
          binding checks, quote consistency checks, and a clear verification
          verdict.
        </p>
      </header>

      <main className="page-grid">
        <section className="panel-stack">
          <VerdictCard
            fileName={fileName}
            result={result}
          />
          <AdvancedPanel result={result} />
          <InputPanel
            onInputChange={handleInputChange}
            rawInput={rawInput}
          />
        </section>

        <section className="panel-stack">
          <CheckList
            checks={result.checks}
            verification={result.verification}
          />
        </section>
      </main>
    </div>
  );
}
