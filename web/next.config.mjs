/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  output: "standalone", // small self-contained server for the Docker image
  // The sample scan is the home page now; keep old /demo links working with a real HTTP redirect.
  redirects: async () => [{ source: "/demo", destination: "/", permanent: false }],
};

export default nextConfig;
