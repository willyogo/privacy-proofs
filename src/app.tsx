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
  const [collateralInput, setCollateralInput] = useState("");
  const [collateralFileName, setCollateralFileName] = useState<string | undefined>(
    undefined,
  );
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

  function handleCollateralInputChange(nextValue: string, nextFileName?: string) {
    setCollateralInput(nextValue);
    setCollateralFileName(nextFileName);
  }

  async function handleVerify() {
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    setIsVerifying(true);

    const nextResult = await parseReportSource(
      rawInput,
      fileName,
      collateralInput,
      collateralFileName,
    );

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
        <section className="panel-stack">
          <VerdictCard
            fileName={fileName}
            result={result}
          />
          <AdvancedPanel result={result} />
          <InputPanel
            collateralFileName={collateralFileName}
            collateralInput={collateralInput}
            fileName={fileName}
            isVerifying={isVerifying}
            onCollateralInputChange={handleCollateralInputChange}
            onInputChange={handleReportInputChange}
            onVerify={handleVerify}
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
