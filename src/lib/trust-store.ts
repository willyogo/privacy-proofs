export type TrustDomain = "app" | "intel" | "nvidia";

const PINNED_ROOT_FINGERPRINTS: Record<TrustDomain, string[]> = {
  app: ["27a57326a2cb9b8a7f293347180afb6162771bb9ec06d7bea5c9e2a3aaec8bdf"],
  intel: [
    "bf85a53fc08f84cb1f73a4f75f48af566e30ac040699ba0ec1b8d593c05b56fc",
    "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3",
  ],
  nvidia: ["102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48"],
};

export function getPinnedRootFingerprints(domain: TrustDomain): string[] {
  return PINNED_ROOT_FINGERPRINTS[domain];
}
