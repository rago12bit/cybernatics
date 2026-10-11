// Mermaid's browser build for the diagram frame. The frame asks for it with ?v=<version>, so it can
// be cached for good.
import { mermaidBundle } from "@/lib/mermaid-bundle";

export function GET() {
  return new Response(new Uint8Array(mermaidBundle()), {
    headers: {
      "Content-Type": "text/javascript; charset=utf-8",
      "Cache-Control": "public, max-age=31536000, immutable",
    },
  });
}
