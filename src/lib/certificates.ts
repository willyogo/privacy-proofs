import {
  X509Certificate,
  X509ChainBuilder,
} from "@peculiar/x509";
import type {
  CheckAuthority,
  CheckResult,
  CheckSeverity,
  CheckSource,
} from "./check-result";
import { sha256Hex } from "./crypto";
import {
  getPinnedRootFingerprints,
  getPinnedRootPemCertificates,
  type TrustDomain,
} from "./trust-store";

type CertificateValidationOptions = {
  bundle: string;
  bundleLabel: string;
  domain: TrustDomain;
  jsonPath: string;
  severity?: CheckSeverity;
  source?: CheckSource;
};

type CertificateValidationResult = {
  chain?: X509Certificate[];
  checks: CheckResult[];
};

export async function validateCertificateChain({
  bundle,
  bundleLabel,
  domain,
  jsonPath,
  severity = "blocking",
  source = "local",
}: CertificateValidationOptions): Promise<CertificateValidationResult> {
  const checks: CheckResult[] = [];
  const pems = splitPemBundle(bundle);

  if (pems.length === 0) {
    return {
      checks: [
        buildCheck({
          description: `${bundleLabel} does not contain a PEM certificate chain.`,
          domain: certificateDomain(domain),
          id: `${domain}-certificate-shape`,
          jsonPath,
          label: `Parse ${bundleLabel}`,
          severity,
          source,
          status: "fail",
        }),
      ],
    };
  }

  let certificates: X509Certificate[];
  try {
    certificates = pems.map((pem) => new X509Certificate(pem));
  } catch (error) {
    return {
      checks: [
        buildCheck({
          description:
            error instanceof Error
              ? `${bundleLabel} contains an invalid X.509 certificate: ${error.message}`
              : `${bundleLabel} contains an invalid X.509 certificate.`,
          domain: certificateDomain(domain),
          id: `${domain}-certificate-shape`,
          jsonPath,
          label: `Parse ${bundleLabel}`,
          severity,
          source,
          status: "fail",
        }),
      ],
    };
  }

  checks.push(
    buildCheck({
      description: `${bundleLabel} contains ${certificates.length} PEM certificates.`,
      domain: certificateDomain(domain),
      id: `${domain}-certificate-shape`,
      jsonPath,
      label: `Parse ${bundleLabel}`,
      severity,
      source,
      status: "pass",
    }),
  );

  const trustAnchors = parsePinnedRoots(domain);
  let chain: X509Certificate[];
  try {
    chain = await buildBestCertificateChain(certificates, trustAnchors);
  } catch (error) {
    return {
      checks: [
        ...checks,
        buildCheck({
          description:
            error instanceof Error
              ? `${bundleLabel} did not build into a valid issuer chain: ${error.message}`
              : `${bundleLabel} did not build into a valid issuer chain.`,
          domain: certificateDomain(domain),
          id: `${domain}-certificate-chain`,
          jsonPath,
          label: `Validate ${bundleLabel} chain`,
          severity,
          source,
          status: "fail",
        }),
      ],
    };
  }

  checks.push(
    buildCheck({
      description: `${bundleLabel} built into a ${chain.length}-certificate issuer chain.`,
      domain: certificateDomain(domain),
      id: `${domain}-certificate-chain`,
      jsonPath,
      label: `Validate ${bundleLabel} chain`,
      severity,
      source,
      status: "pass",
    }),
  );

  const now = new Date();
  const expiredCertificate = chain.find(
    (certificate) => now < certificate.notBefore || now > certificate.notAfter,
  );

  checks.push(
    buildCheck({
      description: expiredCertificate
        ? `${bundleLabel} includes a certificate outside its validity window.`
        : `${bundleLabel} certificates are within their validity windows.`,
      domain: certificateDomain(domain),
      id: `${domain}-certificate-validity`,
      jsonPath,
      label: `Check ${bundleLabel} validity window`,
      severity,
      source,
      status: expiredCertificate ? "fail" : "pass",
    }),
  );

  const root = chain.at(-1);
  const expectedFingerprints = getPinnedRootFingerprints(domain);
  const actualFingerprint =
    root !== undefined ? sha256Hex(new Uint8Array(root.rawData)) : undefined;
  const anchoredToPinnedRoot =
    actualFingerprint !== undefined && expectedFingerprints.includes(actualFingerprint);

  checks.push(
    buildCheck({
      description:
        anchoredToPinnedRoot
          ? `${bundleLabel} terminates at the pinned ${domain} trust anchor.`
          : `${bundleLabel} does not terminate at the pinned ${domain} trust anchor.`,
      domain: certificateDomain(domain),
      id: `${domain}-root-pin`,
      jsonPath,
      label: `Check ${bundleLabel} root pin`,
      severity,
      source,
      status: anchoredToPinnedRoot ? "pass" : "fail",
    }),
  );

  return {
    chain,
    checks,
  };
}

export function splitPemBundle(bundle: string): string[] {
  return bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

async function buildBestCertificateChain(
  certificates: X509Certificate[],
  trustAnchors: X509Certificate[],
): Promise<X509Certificate[]> {
  const candidates = [...certificates].sort((left, right) => {
    const leftIssuedCount = countIssuedCertificates(left, certificates);
    const rightIssuedCount = countIssuedCertificates(right, certificates);
    if (leftIssuedCount !== rightIssuedCount) {
      return leftIssuedCount - rightIssuedCount;
    }

    return Number(isSelfSigned(left)) - Number(isSelfSigned(right));
  });

  let bestChain: X509Certificate[] | undefined;
  let lastError: unknown;

  for (const leaf of candidates) {
    try {
      const chain = Array.from(
        await new X509ChainBuilder({
          certificates: uniqueCertificates([
            ...certificates.filter((certificate) => certificate !== leaf),
            ...trustAnchors,
          ]),
        }).build(leaf),
      );

      if (!bestChain || chain.length > bestChain.length) {
        bestChain = chain;
      }
    } catch (error) {
      lastError = error;
    }
  }

  if (bestChain) {
    return bestChain;
  }

  throw lastError instanceof Error ? lastError : new Error("No issuer chain could be built.");
}

function countIssuedCertificates(
  issuerCandidate: X509Certificate,
  certificates: X509Certificate[],
): number {
  return certificates.filter(
    (certificate) =>
      certificate !== issuerCandidate && certificate.issuer === issuerCandidate.subject,
  ).length;
}

function isSelfSigned(certificate: X509Certificate): boolean {
  return certificate.subject === certificate.issuer;
}

function parsePinnedRoots(domain: TrustDomain): X509Certificate[] {
  return getPinnedRootPemCertificates(domain).map((pem) => new X509Certificate(pem));
}

function uniqueCertificates(certificates: X509Certificate[]): X509Certificate[] {
  const seen = new Set<string>();

  return certificates.filter((certificate) => {
    const fingerprint = sha256Hex(new Uint8Array(certificate.rawData));
    if (seen.has(fingerprint)) {
      return false;
    }

    seen.add(fingerprint);
    return true;
  });
}

function certificateDomain(domain: TrustDomain): CheckResult["domain"] {
  if (domain === "app") {
    return "app-cert";
  }

  if (domain === "intel") {
    return "tdx";
  }

  return "nvidia";
}

type BuildCheckInput = Omit<CheckResult, "authority"> & {
  authority?: CheckAuthority;
};

function buildCheck(check: BuildCheckInput): CheckResult {
  return {
    ...check,
    authority: check.authority ?? inferAuthority(check.source),
  };
}

function inferAuthority(source: CheckResult["source"]): CheckAuthority {
  if (source === "online") {
    return "vendor";
  }

  if (source === "embedded") {
    return "provenance";
  }

  return "cryptographic";
}
