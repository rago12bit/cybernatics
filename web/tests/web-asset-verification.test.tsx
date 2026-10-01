// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WebAssetVerification } from "../components/WebAssetVerification";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const PENDING = {
  asset_id: "a1",
  domain: "example.com",
  method: "dns_txt",
  status: "pending",
  record_name: "_bulwark-challenge.example.com",
  record_value: "bulwark-site-verification=tok123",
  well_known_url: null,
  file_content: null,
  created_at: "2026-10-01T00:00:00Z",
  verified_at: null,
  last_checked_at: null,
  last_error: null,
};

async function mount(props: { assetId?: string } = {}) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<WebAssetVerification {...props} />));
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

describe("WebAssetVerification", () => {
  it("shows the registration form when there is no assetId", async () => {
    const host = await mount();
    expect(host.querySelector("#wav-domain")).not.toBeNull();
    expect(Array.from(host.querySelectorAll("button")).some((b) => b.textContent?.includes("Register"))).toBe(true);
  });

  it("registering a domain posts to /assets/web and shows DNS instructions", async () => {
    let sent: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (String(url).endsWith("/assets/web")) {
          sent = JSON.parse(init!.body as string);
          return json(PENDING);
        }
        return json({});
      }),
    );
    const host = await mount();
    const domainInput = host.querySelector("#wav-domain") as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    await act(async () => {
      setValue.call(domainInput, "example.com");
      domainInput.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const registerBtn = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Register"))!;
    await act(async () => registerBtn.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(sent).toMatchObject({ domain: "example.com", method: "dns_txt" });
    expect(host.textContent).toContain("_bulwark-challenge.example.com");
    expect(host.textContent).toContain("bulwark-site-verification=tok123");
  });

  it("loads an existing verification by assetId and shows its status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(PENDING)));
    const host = await mount({ assetId: "a1" });
    expect(host.textContent).toContain("Not yet verified");
  });

  it("Check now calls /verify and reflects a verified result", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (String(url).includes("/verify") && init?.method === "POST") {
          return json({ ...PENDING, status: "verified", verified_at: "2026-10-01T01:00:00Z" });
        }
        return json(PENDING);
      }),
    );
    const host = await mount({ assetId: "a1" });
    const checkBtn = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Check now"))!;
    await act(async () => checkBtn.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(host.textContent).toContain("Verified");
  });

  it("shows the last error when verification fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json({ ...PENDING, status: "failed", last_error: "no record found" })),
    );
    const host = await mount({ assetId: "a1" });
    expect(host.textContent).toContain("Verification failed");
    expect(host.textContent).toContain("no record found");
  });

  it("shows well-known instructions when that method was chosen", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({
          ...PENDING,
          method: "well_known",
          record_name: null,
          record_value: null,
          well_known_url: "https://example.com/.well-known/bulwark-verification.txt",
          file_content: "tok123",
        }),
      ),
    );
    const host = await mount({ assetId: "a1" });
    expect(host.textContent).toContain("https://example.com/.well-known/bulwark-verification.txt");
    expect(host.textContent).toContain("tok123");
  });
});
