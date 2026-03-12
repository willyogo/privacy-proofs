import { useRef, useState, useTransition } from "react";
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
  const [isVerifying, setIsVerifying] = useState(false);
  const [, startTransition] = useTransition();
  const requestIdRef = useRef(0);

  function handleReportInputChange(nextValue: string, nextFileName?: string) {
    setRawInput(nextValue);
    setFileName(nextFileName);

    if (nextValue.trim().length === 0) {
      setResult(createIdleParseResult());
    }
  }

  async function handleVerify() {
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    setIsVerifying(true);

    const nextResult = await parseReportSource(rawInput, fileName);

    if (requestId !== requestIdRef.current) {
      return;
    }

    startTransition(() => {
      setResult(nextResult);
    });
    setIsVerifying(false);
  }

  return (
    <div className="page-shell">
      <div className="page-overlay" />
      <header className="page-header">
        <img
          alt="Venice logo"
          className="brand-logo"
          src="/venice-logotype.svg"
        />
        <div className="hero-block">
          <h1>Attestation Verifier</h1>
          <p className="hero-copy">
            Paste or upload a Venice attestation report to run browser-side
            structural, binding, certificate, and cryptographic checks with a
            verdict that never trusts embedded claims on their own.
          </p>
        </div>
      </header>

      <main className="page-grid">
        <InputPanel
          className="page-section-input"
          fileName={fileName}
          isVerifying={isVerifying}
          onInputChange={handleReportInputChange}
          onVerify={handleVerify}
          rawInput={rawInput}
        />
        <VerdictCard
          className="page-section-verdict"
          fileName={fileName}
          result={result}
        />
        <CheckList
          checks={result.checks}
          className="page-section-checks"
          verification={result.verification}
        />
        <AdvancedPanel
          className="page-section-overview"
          result={result}
        />
      </main>
    </div>
  );
}
