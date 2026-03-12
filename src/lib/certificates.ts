import {
  X509Certificate,
  X509ChainBuilder,
} from "@peculiar/x509";
import type { CheckResult } from "./check-result";
import { sha256Hex } from "./crypto";
import { getPinnedRootFingerprints, type TrustDomain } from "./trust-store";

type CertificateValidationOptions = {
  bundle: string;
  bundleLabel: string;
  domain: TrustDomain;
  jsonPath: string;
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
          severity: "blocking",
          source: "local",
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
          severity: "blocking",
          source: "local",
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
      severity: "blocking",
      source: "local",
      status: "pass",
    }),
  );

  let chain: X509Certificate[];
  try {
    chain = await buildBestCertificateChain(certificates);
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
          severity: "blocking",
          source: "local",
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
      severity: "blocking",
      source: "local",
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
      severity: "blocking",
      source: "local",
      status: expiredCertificate ? "fail" : "pass",
    }),
  );

  const root = chain.at(-1);
  const expectedFingerprints = getPinnedRootFingerprints(domain);
  const providedPinnedRoot = certificates.find(
    (certificate) => {
      const fingerprint = sha256Hex(new Uint8Array(certificate.rawData));
      return expectedFingerprints.includes(fingerprint);
    },
  );
  const actualFingerprint =
    root !== undefined ? sha256Hex(new Uint8Array(root.rawData)) : undefined;
  const effectiveRoot =
    actualFingerprint && expectedFingerprints.includes(actualFingerprint)
      ? root
      : providedPinnedRoot;

  if (
    effectiveRoot &&
    chain.at(-1) !== effectiveRoot &&
    !chain.some((certificate) => certificate === effectiveRoot)
  ) {
    chain = [...chain, effectiveRoot];
  }

  checks.push(
    buildCheck({
      description:
        effectiveRoot !== undefined
          ? `${bundleLabel} terminates at the pinned ${domain} trust anchor.`
          : `${bundleLabel} does not terminate at the pinned ${domain} trust anchor.`,
      domain: certificateDomain(domain),
      id: `${domain}-root-pin`,
      jsonPath,
      label: `Check ${bundleLabel} root pin`,
      severity: "blocking",
      source: "local",
      status: effectiveRoot !== undefined ? "pass" : "fail",
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
          certificates: certificates.filter((certificate) => certificate !== leaf),
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

function certificateDomain(domain: TrustDomain): CheckResult["domain"] {
  if (domain === "app") {
    return "app-cert";
  }

  if (domain === "intel") {
    return "tdx";
  }

  return "nvidia";
}

function buildCheck(check: CheckResult): CheckResult {
  return check;
}
