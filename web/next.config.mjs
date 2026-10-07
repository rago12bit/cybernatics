/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  output: "standalone", // small self-contained server for the Docker image
  // Dev-server only (ignored in the production build above): Playwright's E2E config
  // (playwright.config.ts) drives the app via 127.0.0.1, which Next 16 otherwise blocks as a
  // cross-origin dev request by default.
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  // The dev server's floating "N" / "Compiling..." badge comes and goes, so the visual snapshots
  // (tests-e2e/visual.spec.ts) would capture it some runs and not others. Off when Playwright
  // starts the server (playwright.config.ts sets BULWARK_E2E); kept for everyday development.
  ...(process.env.BULWARK_E2E === "1" ? { devIndicators: false } : {}),
  // The product pitch is the home page and the sample scan lives at /sample; keep the old /about
  // and /demo links working with a real HTTP redirect.
  redirects: async () => [
    { source: "/about", destination: "/", permanent: false },
    { source: "/demo", destination: "/sample", permanent: false },
    // RFC 9116 (Week 48 task 2): the well-known path is the canonical location; this just keeps a
    // crawler checking the older, still-common plain /security.txt path pointed at the real file.
    { source: "/security.txt", destination: "/.well-known/security.txt", permanent: true },
    // Public sample build: there is no API, so the app and scan pages explain how to self-host instead.
    ...(process.env.NEXT_PUBLIC_DEMO_ONLY === "1"
      ? [
          { source: "/app", destination: "/self-host", permanent: false },
          { source: "/scans/:path*", destination: "/self-host", permanent: false },
        ]
      : []),
  ],
};

export default nextConfig;
