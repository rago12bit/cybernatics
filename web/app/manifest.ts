import type { MetadataRoute } from "next";

// Installable and themed: the browser's own UI takes the site's near-black, and a saved shortcut opens the app.
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Bulwark: security scanning without the noise",
    short_name: "Bulwark",
    description: "Sandboxed open-source scanners, merged into one report that shows which scanners agree.",
    start_url: "/app",
    display: "standalone",
    background_color: "#131310",
    theme_color: "#131310",
    icons: [
      { src: "/icon.svg", sizes: "any", type: "image/svg+xml" },
      { src: "/apple-icon.png", sizes: "180x180", type: "image/png" },
    ],
  };
}
