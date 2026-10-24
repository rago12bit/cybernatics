import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib/site";

// The public site's pages. A sitemap needs absolute URLs, so it is empty until NEXT_PUBLIC_SITE_URL says
// where the site is served.
const PUBLIC_PAGES = ["/", "/how-it-works", "/integrations", "/security", "/compare", "/self-host", "/community", "/migrate", "/sample"];

export default function sitemap(): MetadataRoute.Sitemap {
  if (!SITE_URL) return [];
  return PUBLIC_PAGES.map((path) => ({
    url: `${SITE_URL}${path === "/" ? "" : path}`,
    changeFrequency: "monthly",
    priority: path === "/" ? 1 : 0.7,
  }));
}
