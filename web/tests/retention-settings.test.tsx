// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RetentionSettings } from "../components/RetentionSettings";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<RetentionSettings />));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("RetentionSettings", () => {
  it("shows the current retention window once loaded", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ org_id: "o1", retention_days: 7 })));
    const host = await mount();
    const input = host.querySelector("#retention-days") as HTMLInputElement;
    expect(input.value).toBe("7");
  });

  it("Save calls the PUT endpoint with the new value and shows a confirmation", async () => {
    let sent: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "PUT") {
          sent = JSON.parse(init.body as string);
          return json({ org_id: "o1", retention_days: 30 });
        }
        return json({ org_id: "o1", retention_days: 7 });
      }),
    );
    const host = await mount();
    const input = host.querySelector("#retention-days") as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    await act(async () => {
      setValue.call(input, "30");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const save = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Save")!;
    await act(async () => save.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(sent).toMatchObject({ retention_days: 30 });
    expect(host.textContent).toContain("Saved.");
  });

  it("rejects a value below 1 without calling the API", async () => {
    const fetchMock = vi.fn(async () => json({ org_id: "o1", retention_days: 7 }));
    vi.stubGlobal("fetch", fetchMock);
    const host = await mount();
    const input = host.querySelector("#retention-days") as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    await act(async () => {
      setValue.call(input, "0");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const callsBefore = fetchMock.mock.calls.length;
    const save = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Save")!;
    await act(async () => save.click());
    expect(fetchMock.mock.calls.length).toBe(callsBefore); // no PUT was attempted
    expect(host.textContent).toContain("at least 1");
  });

  it("shows an error message when the initial load fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "nope" }, 500)));
    const host = await mount();
    expect(host.querySelector('[role="alert"]')).not.toBeNull();
  });
});
