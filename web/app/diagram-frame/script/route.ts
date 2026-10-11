// What runs in the diagram frame: draw the Mermaid source the framing page posts, then report the
// drawing's size (or a failure) back to it. Only messages from this origin's own parent count.
const SCRIPT = `"use strict";
(() => {
  const box = document.getElementById("diagram");
  // Dark: the diagram sits on the app's dark page, and the default theme's arrows vanish on it.
  mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "dark" });
  let drawn = 0;
  addEventListener("message", async (event) => {
    if (event.origin !== location.origin || event.source !== parent) return;
    const { source, request } = event.data || {};
    if (typeof source !== "string") return;
    const reply = (body) => parent.postMessage({ type: "bulwark-diagram", request, ...body }, location.origin);
    try {
      const { svg } = await mermaid.render("tm" + ++drawn, source);
      box.innerHTML = svg; // Mermaid's own output, sanitized by it (securityLevel "strict")
      const view = box.querySelector("svg")?.viewBox.baseVal;
      reply({ ok: true, width: view?.width || 0, height: view?.height || 0 });
    } catch {
      box.replaceChildren();
      reply({ ok: false });
    }
  });
})();
`;

export function GET() {
  return new Response(SCRIPT, { headers: { "Content-Type": "text/javascript; charset=utf-8" } });
}
