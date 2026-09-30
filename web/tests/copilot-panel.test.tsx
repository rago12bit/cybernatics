// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CopilotPanel } from "../components/CopilotPanel";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const CONVERSATION = {
  id: "conv-1", asset_id: "a1", context_kind: null, context_id: null,
  created_at: "2026-09-30T00:00:00Z", last_message_at: "2026-09-30T00:00:00Z",
};

async function mount(assetId = "a1") {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<CopilotPanel assetId={assetId} />));
  return host;
}

async function open(host: HTMLElement) {
  const trigger = host.querySelector("button.ds-copilot-trigger") as HTMLButtonElement;
  await act(async () => trigger.click());
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
}

async function type(host: HTMLElement, text: string) {
  const input = host.querySelector(".ds-copilot-input input") as HTMLInputElement;
  const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
  await act(async () => {
    setValue.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function send(host: HTMLElement) {
  const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Send")!;
  await act(async () => button.click());
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("CopilotPanel", () => {
  it("shows a trigger button and the panel is closed until clicked", async () => {
    const host = await mount();
    expect(host.querySelector(".ds-copilot-panel")).toBeNull();
    expect(host.textContent).toContain("Copilot");
  });

  it("opening the panel starts a conversation", async () => {
    let posted = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/copilot/conversations") && !url.includes("/messages")) {
          posted = true;
          return json(CONVERSATION);
        }
        if (url.includes("/messages")) return json([]);
        return json({ detail: "not found" }, 404);
      }),
    );
    const host = await mount();
    await open(host);
    expect(posted).toBe(true);
    expect(host.querySelector(".ds-copilot-panel")).not.toBeNull();
  });

  it("sending a question shows the cited answer with a clickable issue citation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/copilot/conversations") && !url.includes("/messages")) {
          return json(CONVERSATION);
        }
        if (url.includes("/messages") && (!init || init.method === undefined)) return json([]);
        if (init?.method === "POST" && url.includes("/messages")) {
          return json({
            id: "m1", role: "assistant", content: "SQL injection is the top risk.",
            citations: [{ kind: "issue", issue_id: "ISS-1", path: null, line: null }],
            created_at: "2026-09-30T00:01:00Z",
          });
        }
        return json({ detail: "not found" }, 404);
      }),
    );
    const host = await mount();
    await open(host);
    await type(host, "what's the top risk?");
    await send(host);
    expect(host.textContent).toContain("SQL injection is the top risk.");
    const link = host.querySelector("a.ds-copilot-citation") as HTMLAnchorElement | null;
    expect(link).not.toBeNull();
    expect(link!.getAttribute("href")).toBe("/app/projects/a1/issues/ISS-1");
  });

  it("renders a code citation as plain text, not a link", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/copilot/conversations") && !url.includes("/messages")) {
          return json(CONVERSATION);
        }
        if (url.includes("/messages") && (!init || init.method === undefined)) return json([]);
        if (init?.method === "POST" && url.includes("/messages")) {
          return json({
            id: "m1", role: "assistant", content: "Here's the relevant code.",
            citations: [{ kind: "code", issue_id: null, path: "app/users.py", line: 12 }],
            created_at: "2026-09-30T00:01:00Z",
          });
        }
        return json({ detail: "not found" }, 404);
      }),
    );
    const host = await mount();
    await open(host);
    await type(host, "show me the code");
    await send(host);
    expect(host.querySelector("a.ds-copilot-citation")).toBeNull();
    expect(host.textContent).toContain("app/users.py:12");
  });

  it("shows an error message when the copilot is disabled", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json({ detail: "the copilot is not enabled on this server" }, 409)),
    );
    const host = await mount();
    await open(host);
    expect(host.textContent).toContain("not enabled on this server");
  });

  it("closing the panel hides it again", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST") return json(CONVERSATION);
        return json([]);
      }),
    );
    const host = await mount();
    await open(host);
    expect(host.querySelector(".ds-copilot-panel")).not.toBeNull();
    const closeBtn = host.querySelector(".ds-copilot-close") as HTMLButtonElement;
    await act(async () => closeBtn.click());
    expect(host.querySelector(".ds-copilot-panel")).toBeNull();
  });
});
