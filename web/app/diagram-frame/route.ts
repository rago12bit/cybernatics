// The document a threat-model diagram is drawn in (DiagramView, components/ThreatModelEditor.tsx).
//
// Mermaid's SVG carries a <style> element and style="" attributes, and Mermaid inserts a copy into
// its document to measure text while it renders. The app's CSP (proxy.ts) allows neither, so in
// production the diagram came out unstyled: black boxes and arrows that could not be seen. This
// frame has its own policy instead: inline styles, and scripts only from this origin (Mermaid's own
// browser build and script/route.ts). The app's policy stays as strict as it was. It takes the
// diagram's source from the page that frames it, by postMessage, and nothing else.
import { MERMAID_VERSION } from "@/lib/mermaid-bundle";

const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="color-scheme" content="dark">
<title>Threat model diagram</title>
<style>
  html, body { margin: 0; background: transparent; }
  #diagram svg { display: block; width: 100%; height: auto; }
</style>
<script defer src="/diagram-frame/mermaid?v=${MERMAID_VERSION}"></script>
<script defer src="/diagram-frame/script"></script>
</head>
<body><div id="diagram"></div></body>
</html>
`;

export function GET() {
  return new Response(HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
