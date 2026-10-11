// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ThreatModelEditor } from "../components/ThreatModelEditor";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;


function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const MODEL = {
  asset_id: "a1",
  mermaid: "flowchart LR\n    user([User])",
  stride: [
    { element: "User", element_kind: "external_entity", category: "Spoofing", prompt: "Can this actor be impersonated?" },
  ],
  version: 1,
  source: "generated",
  updated_at: "2026-09-30T00:00:00Z",
  updated_by: null,
};

async function mount(assetId = "a1") {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<ThreatModelEditor assetId={assetId} />));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("ThreatModelEditor", () => {
  it("shows the version, source, and STRIDE table for the current draft", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(MODEL)));
    const host = await mount();
    const text = host.textContent ?? "";
    expect(text).toContain("Version 1");
    expect(text).toContain("generated");
    expect(text).toContain("Can this actor be impersonated?");
    expect(host.querySelector<HTMLIFrameElement>(".ds-tm-diagram iframe")?.getAttribute("src")).toBe("/diagram-frame");
  });

  it("Edit reveals an editable Mermaid textarea and STRIDE inputs seeded from the current draft", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(MODEL)));
    const host = await mount();
    const edit = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Edit")!;
    await act(async () => edit.click());
    const textarea = host.querySelector("#tm-mermaid") as HTMLTextAreaElement;
    expect(textarea.value).toContain("user([User])");
    const input = host.querySelector(".ds-tm-table input") as HTMLInputElement;
    expect(input.value).toBe("User");
  });

  it("Save calls the PUT endpoint and shows the edited draft as the current one", async () => {
    let saved: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "PUT") {
          saved = JSON.parse(init.body as string);
          return json({ ...MODEL, ...(saved as Record<string, unknown>), version: 2, source: "edited" });
        }
        return json(MODEL);
      }),
    );
    const host = await mount();
    const edit = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Edit")!;
    await act(async () => edit.click());
    const textarea = host.querySelector("#tm-mermaid") as HTMLTextAreaElement;
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")!.set!;
    await act(async () => {
      setValue.call(textarea, "flowchart LR\n    x");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const save = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Save")!;
    await act(async () => save.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(saved).toMatchObject({ mermaid: "flowchart LR\n    x" });
    expect(host.textContent).toContain("Version 2");
    expect(host.textContent).toContain("edited");
  });

  it("Regenerate calls the regenerate endpoint and replaces the draft", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/regenerate")) {
          return json({ ...MODEL, version: 3, mermaid: "flowchart LR\n    fresh" });
        }
        return json(MODEL);
      }),
    );
    const host = await mount();
    const regen = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Regenerate"))!;
    await act(async () => regen.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(host.textContent).toContain("Version 3");
  });

  describe("the diagram frame", () => {
    // The diagram is drawn in its own frame (app/diagram-frame), whose CSP allows Mermaid's inline
    // styles; the page posts it the source and takes back the drawing's size or a failure.
    async function framed() {
      vi.stubGlobal("fetch", vi.fn(async () => json(MODEL)));
      const host = await mount();
      const iframe = host.querySelector<HTMLIFrameElement>(".ds-tm-diagram iframe")!;
      const posted: unknown[] = [];
      vi.spyOn(iframe.contentWindow!, "postMessage").mockImplementation((m: unknown) => void posted.push(m));
      await act(async () => iframe.dispatchEvent(new Event("load")));
      const reply = (data: object, source: Window | null = iframe.contentWindow) =>
        act(async () => {
          window.dispatchEvent(new MessageEvent("message", { data: { type: "bulwark-diagram", ...data }, origin: window.location.origin, source }));
        });
      return { host, iframe, posted, reply };
    }

    it("posts the source once the frame has loaded, and sizes the frame to the drawing", async () => {
      const { iframe, posted, reply } = await framed();
      expect(posted).toEqual([{ source: MODEL.mermaid, request: 1 }]);
      await reply({ request: 1, ok: true, width: 400, height: 100 });
      expect(iframe.style.maxWidth).toBe("400px");
      expect(iframe.style.aspectRatio).toBe("400 / 100");
      expect(iframe.hidden).toBe(false);
    });

    it("shows the raw source when the frame could not draw it", async () => {
      const { host, iframe, reply } = await framed();
      await reply({ request: 1, ok: false });
      expect(host.querySelector('[role="alert"]')?.textContent).toContain("Could not render this diagram");
      expect(host.querySelector(".ds-tm-raw")?.textContent).toBe(MODEL.mermaid);
      expect(iframe.hidden).toBe(true);
    });

    it("ignores replies from anything but its own frame, and replies to an older draw", async () => {
      const { host, iframe, reply } = await framed();
      await reply({ request: 1, ok: false }, window); // not the frame
      await reply({ request: 0, ok: false }); // not the latest request
      expect(host.querySelector('[role="alert"]')).toBeNull();
      expect(iframe.hidden).toBe(false);
    });
  });
});
