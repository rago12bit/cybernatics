import { API_URL } from "./api";

// Build-time switch for the public sample site: no API, no scanning, no sign-in. The flag is inlined at
// build (NEXT_PUBLIC_*), so a demo build cannot be talked into calling an API it was never given.
export const DEMO_ONLY = process.env.NEXT_PUBLIC_DEMO_ONLY === "1";

export const APP_HREF = DEMO_ONLY ? "/self-host" : "/app";
export const APP_CTA = DEMO_ONLY ? "Run it yourself →" : "Open the app →";
export const APP_NAV = DEMO_ONLY ? "Run it yourself" : "App";
export const DOCS_HREF = DEMO_ONLY ? "/self-host" : `${API_URL}/docs`; // the API only exists when you run it

// Public links are configured at build time and never hard-coded, so nothing is published by accident.
// Only https: URLs (repository) and mailto: / https: (contact) are accepted; anything else is ignored.
export function safePublicLink(raw: string | undefined, allowMailto: boolean): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw.trim());
    if (u.protocol === "https:" && !u.username && !u.password) return u.toString();
    if (allowMailto && u.protocol === "mailto:" && /^mailto:[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(u.href)) return u.href;
  } catch {
    /* not a URL */
  }
  return null;
}
export const REPO_URL = safePublicLink(process.env.NEXT_PUBLIC_REPO_URL, false);
export const CONTACT_URL = safePublicLink(process.env.NEXT_PUBLIC_CONTACT_URL, true);
// Where the public site is served, for link previews, the sitemap and robots.txt. Unset (a self-hosted
// app on a private network), those use relative links only and the sitemap stays empty.
export const SITE_URL = safePublicLink(process.env.NEXT_PUBLIC_SITE_URL, false)?.replace(/\/+$/, "") ?? null;
