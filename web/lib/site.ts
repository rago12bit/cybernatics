import { API_URL } from "./api";

// Build-time switch for the public sample site: no API, no scanning, no sign-in. The flag is inlined at
// build (NEXT_PUBLIC_*), so a demo build cannot be talked into calling an API it was never given.
export const DEMO_ONLY = process.env.NEXT_PUBLIC_DEMO_ONLY === "1";

export const APP_HREF = DEMO_ONLY ? "/self-host" : "/app";
export const APP_CTA = DEMO_ONLY ? "Run it yourself →" : "Open the app →";
export const APP_NAV = DEMO_ONLY ? "Run it yourself" : "App";
export const DOCS_HREF = DEMO_ONLY ? "/self-host" : `${API_URL}/docs`; // the API only exists when you run it
