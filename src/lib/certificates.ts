import {
  CRLDistributionPointsExtension,
  X509Certificate,
  X509ChainBuilder,
  X509Crl,
} from "@peculiar/x509";
import type { CheckResult, CheckSource } from "./check-result";
import { sha256Hex, fromBase64, toBase64 } from "./crypto";
import { getPinnedRootFingerprints, type TrustDomain } from "./trust-store";

type CertificateValidationOptions = {
  bundle: string;
  bundleLabel: string;
  collateralCrlPem?: string;
  domain: TrustDomain;
  jsonPath: string;
};

type CertificateValidationResult = {
  chain?: X509Certificate[];
  checks: CheckResult[];
  fetchedCollateral: boolean;
  revocationChecked: boolean;
};

const collateralCache = new Map<string, string>();

export async function validateCertificateChain({
  bundle,
  bundleLabel,
  collateralCrlPem,
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
      fetchedCollateral: false,
      revocationChecked: false,
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
      fetchedCollateral: false,
      revocationChecked: false,
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
      fetchedCollateral: false,
      revocationChecked: false,
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

  const { checks: revocationChecks, fetchedCollateral, revocationChecked } =
    await validateRevocation({
      chain,
      collateralCrlPem,
      domain,
      jsonPath,
    });

  return {
    chain,
    checks: [...checks, ...revocationChecks],
    fetchedCollateral,
    revocationChecked,
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

async function validateRevocation({
  chain,
  collateralCrlPem,
  domain,
  jsonPath,
}: {
  chain: X509Certificate[];
  collateralCrlPem?: string;
  domain: TrustDomain;
  jsonPath: string;
}): Promise<{
  checks: CheckResult[];
  fetchedCollateral: boolean;
  revocationChecked: boolean;
}> {
  const leaf = chain[0];
  const issuer = chain[1];
  const checks: CheckResult[] = [];

  if (!leaf || !issuer) {
    return {
      checks,
      fetchedCollateral: false,
      revocationChecked: false,
    };
  }

  const crlResult =
    collateralCrlPem !== undefined
      ? { pem: collateralCrlPem, source: "local" as CheckSource }
      : await fetchFirstCrl(leaf);

  if (!crlResult) {
    checks.push(
      buildCheck({
        description:
          "No certificate revocation list was available, so revocation could not be checked locally.",
        domain: "collateral",
        id: `${domain}-revocation`,
        jsonPath,
        label: "Check certificate revocation",
        severity: "advisory",
        source: "online-collateral",
        status: "info",
      }),
    );

    return {
      checks,
      fetchedCollateral: false,
      revocationChecked: false,
    };
  }

  try {
    const crl = new X509Crl(crlResult.pem);
    const signatureValid = await crl.verify({ publicKey: issuer });
    const revoked = crl.findRevoked(leaf) !== null;

    checks.push(
      buildCheck({
        description: signatureValid
          ? "The fetched certificate revocation list signature is valid."
          : "The fetched certificate revocation list signature is invalid.",
        domain: "collateral",
        id: `${domain}-revocation-signature`,
        jsonPath,
        label: "Validate revocation list signature",
        severity: "advisory",
        source: crlResult.source,
        status: signatureValid ? "pass" : "fail",
      }),
    );

    checks.push(
      buildCheck({
        description: revoked
          ? "The leaf certificate is listed as revoked."
          : "The leaf certificate is not listed as revoked.",
        domain: "collateral",
        id: `${domain}-revocation-status`,
        jsonPath,
        label: "Check revocation status",
        severity: "blocking",
        source: crlResult.source,
        status: !signatureValid || revoked ? "fail" : "pass",
      }),
    );

    return {
      checks,
      fetchedCollateral: crlResult.source === "online-collateral",
      revocationChecked: signatureValid,
    };
  } catch (error) {
    checks.push(
      buildCheck({
        description:
          error instanceof Error
            ? `The revocation list could not be parsed: ${error.message}`
            : "The revocation list could not be parsed.",
        domain: "collateral",
        id: `${domain}-revocation-parse`,
        jsonPath,
        label: "Parse revocation list",
        severity: "advisory",
        source: crlResult.source,
        status: "fail",
      }),
    );

    return {
      checks,
      fetchedCollateral: crlResult.source === "online-collateral",
      revocationChecked: false,
    };
  }
}

async function fetchFirstCrl(
  certificate: X509Certificate,
): Promise<{ pem: string; source: CheckSource } | undefined> {
  const extension = certificate.getExtension(CRLDistributionPointsExtension);
  const urls =
    extension?.distributionPoints.flatMap((distributionPoint) =>
      distributionPoint.distributionPoint?.fullName
        ?.map((item) => item.uniformResourceIdentifier)
        .filter((value): value is string => typeof value === "string"),
    ) ?? [];

  for (const url of urls) {
    if (typeof url !== "string") {
      continue;
    }

    try {
      const pem = await fetchCachedResource(url);
      return {
        pem: normalizeCrlEncoding(pem),
        source: "online-collateral",
      };
    } catch {
      continue;
    }
  }

  return undefined;
}

async function fetchCachedResource(url: string): Promise<string> {
  const cached = collateralCache.get(url) ?? readLocalStorage(url);
  if (cached) {
    return cached;
  }

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Collateral fetch failed with status ${response.status}.`);
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  const encoded = toBase64(bytes);
  collateralCache.set(url, encoded);
  writeLocalStorage(url, encoded);
  return encoded;
}

function normalizeCrlEncoding(value: string): string {
  if (value.includes("BEGIN X509 CRL")) {
    return value;
  }

  const bytes = fromBase64(value);
  return `-----BEGIN X509 CRL-----\n${wrapBase64(toBase64(bytes))}\n-----END X509 CRL-----`;
}

function wrapBase64(value: string): string {
  return value.match(/.{1,64}/g)?.join("\n") ?? value;
}

function readLocalStorage(key: string): string | undefined {
  if (typeof localStorage !== "object") {
    return undefined;
  }

  const value = localStorage.getItem(`venice-collateral:${key}`);
  return value ?? undefined;
}

function writeLocalStorage(key: string, value: string) {
  if (typeof localStorage !== "object") {
    return;
  }

  localStorage.setItem(`venice-collateral:${key}`, value);
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
