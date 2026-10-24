import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib/site";

// The public pages are for everyone; the app, scan reports and the diagram frame are behind sign-in
// or embedded, and have nothing for a search engine.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/app", "/scans/", "/signin", "/diagram-frame"] },
    ...(SITE_URL ? { sitemap: `${SITE_URL}/sitemap.xml` } : {}),
  };
}
