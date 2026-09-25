/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  output: "standalone", // small self-contained server for the Docker image
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
