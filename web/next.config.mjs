/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  output: "standalone", // small self-contained server for the Docker image
  // Dev-server only (ignored in the production build above): Playwright's E2E config
  // (playwright.config.ts) drives the app via 127.0.0.1, which Next 16 otherwise blocks as a
  // cross-origin dev request by default.
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  // The sample scan is the home page now; keep old /demo links working with a real HTTP redirect.
  redirects: async () => [
    { source: "/demo", destination: "/", permanent: false },
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
