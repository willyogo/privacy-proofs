import { useRef, useState, useTransition } from "react";
import AdvancedPanel from "./components/AdvancedPanel";
import CheckList from "./components/CheckList";
import InputPanel from "./components/InputPanel";
import VerdictCard from "./components/VerdictCard";
import { createIdleParseResult, parseReportSource } from "./lib/normalize";
import type { ParseResult, VerificationMode } from "./lib/types";

const runtimeEnv = (import.meta as ImportMeta & {
  env?: Record<string, string | undefined>;
}).env;

export default function App() {
  const [rawInput, setRawInput] = useState("");
  const [fileName, setFileName] = useState<string | undefined>(undefined);
  const [nvidiaApiKey, setNvidiaApiKey] = useState("");
  const [result, setResult] = useState<ParseResult>(createIdleParseResult());
  const [activeMode, setActiveMode] = useState<VerificationMode | null>(null);
  const [, startTransition] = useTransition();
  const requestIdRef = useRef(0);

  function handleReportInputChange(nextValue: string, nextFileName?: string) {
    setRawInput(nextValue);
    setFileName(nextFileName);

    if (nextValue.trim().length === 0) {
      setResult(createIdleParseResult());
    }
  }

  async function handleVerify(mode: VerificationMode) {
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    setActiveMode(mode);

    const nextResult = await parseReportSource(rawInput, fileName, {
      mode,
      online:
        mode === "online"
          ? {
              intelBaseUrl: sanitizeEnvValue(runtimeEnv?.VITE_INTEL_PCS_BASE_URL),
              nvidiaApiKey:
                sanitizeEnvValue(nvidiaApiKey) ??
                sanitizeEnvValue(runtimeEnv?.VITE_NVIDIA_NRAS_API_KEY),
              nvidiaBaseUrl:
                sanitizeEnvValue(runtimeEnv?.VITE_NVIDIA_NRAS_BASE_URL) ??
                "https://nras.attestation.nvidia.com/v4",
              nvidiaJwksUrl:
                sanitizeEnvValue(runtimeEnv?.VITE_NVIDIA_NRAS_JWKS_URL) ??
                "https://nras.attestation.nvidia.com/.well-known/jwks.json",
            }
          : undefined,
    });

    if (requestId !== requestIdRef.current) {
      return;
    }

    startTransition(() => {
      setResult(nextResult);
    });
    setActiveMode(null);
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
          activeMode={activeMode}
          fileName={fileName}
          onInputChange={handleReportInputChange}
          onNvidiaApiKeyChange={setNvidiaApiKey}
          onVerifyOffline={() => void handleVerify("offline")}
          onVerifyOnline={() => void handleVerify("online")}
          nvidiaApiKey={nvidiaApiKey}
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
          report={result.normalizedReport}
          verification={result.verification}
        />
        <AdvancedPanel
          className="page-section-overview"
          result={result}
        />
      </main>

      <footer className="page-footer">
        <a
          aria-label="View Privacy Proofs on GitHub"
          className="github-link"
          href="https://github.com/willyogo/privacy-proofs"
          rel="noreferrer"
          target="_blank"
        >
          <svg
            aria-hidden="true"
            className="github-link-icon"
            viewBox="0 0 24 24"
          >
            <path
              d="M12 .5C5.649.5.5 5.649.5 12a11.5 11.5 0 0 0 7.863 10.91c.575.106.787-.25.787-.556 0-.274-.01-1-.016-1.962-3.2.696-3.877-1.542-3.877-1.542-.523-1.328-1.278-1.682-1.278-1.682-1.045-.714.08-.699.08-.699 1.156.082 1.765 1.187 1.765 1.187 1.028 1.761 2.697 1.252 3.354.957.104-.744.402-1.253.731-1.541-2.554-.29-5.24-1.277-5.24-5.683 0-1.256.449-2.283 1.184-3.088-.118-.29-.513-1.459.112-3.043 0 0 .966-.309 3.166 1.18a10.94 10.94 0 0 1 2.883-.388c.978.005 1.963.132 2.883.388 2.198-1.489 3.162-1.18 3.162-1.18.627 1.584.232 2.753.114 3.043.737.805 1.182 1.832 1.182 3.088 0 4.417-2.69 5.389-5.252 5.674.413.356.781 1.06.781 2.136 0 1.543-.014 2.787-.014 3.168 0 .309.208.668.793.555A11.502 11.502 0 0 0 23.5 12C23.5 5.649 18.351.5 12 .5Z"
              fill="currentColor"
            />
          </svg>
        </a>
      </footer>
    </div>
  );
}

function sanitizeEnvValue(value?: string): string | undefined {
  return value && value.trim().length > 0 ? value.trim() : undefined;
}
