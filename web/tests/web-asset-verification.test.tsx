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

  it("links the site to a git or archive project when one is picked", async () => {
    let sent: Record<string, unknown> | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (String(url).includes("/assets?")) {
          return json([
            { id: "src1", label: "github.com/acme/shop", source_type: "git" },
            { id: "web1", label: "shop.example.com", source_type: "web" },
            { id: "zip1", label: "shop.zip", source_type: "archive" },
          ]);
        }
        if (String(url).endsWith("/assets/web")) {
          sent = JSON.parse(init!.body as string);
          return json(PENDING);
        }
        return json({});
      }),
    );
    const host = await mount();
    const select = host.querySelector("#wav-source") as HTMLSelectElement;
    // Only code projects can be linked: a web target has no code to confirm against.
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(["Not linked", "github.com/acme/shop", "shop.zip"]);
    const input = host.querySelector("#wav-domain") as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    await act(async () => {
      setValue.call(input, "shop.example.com");
      input.dispatchEvent(new Event("input", { bubbles: true }));
      select.value = "src1";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Register"))!;
    await act(async () => button.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(sent).toEqual({ domain: "shop.example.com", method: "dns_txt", source_asset_id: "src1" });
  });

  it("registers without a link when no project is picked, or none could be listed", async () => {
    let sent: Record<string, unknown> | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (String(url).includes("/assets?")) return json({ detail: "boom" }, 500);
        if (String(url).endsWith("/assets/web")) {
          sent = JSON.parse(init!.body as string);
          return json(PENDING);
        }
        return json({});
      }),
    );
    const host = await mount();
    expect(host.querySelector("#wav-source")).toBeNull();
    const input = host.querySelector("#wav-domain") as HTMLInputElement;
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    await act(async () => {
      setValue.call(input, "example.com");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Register"))!;
    await act(async () => button.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(sent).toEqual({ domain: "example.com", method: "dns_txt" });
  });

  it("changes a registered site's source link in place, keeping its verification", async () => {
    const calls: { url: string; method: string; body: unknown }[] = [];
    const VERIFIED = { ...PENDING, status: "verified", source_asset_id: "src1", source_label: "github.com/acme/shop" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const u = String(url);
        if (u.includes("/assets?")) {
          return json([
            { id: "src1", label: "github.com/acme/shop", source_type: "git" },
            { id: "zip1", label: "shop.zip", source_type: "archive" },
            { id: "web1", label: "shop.example.com", source_type: "web" },
          ]);
        }
        if (u.endsWith("/assets/a1/source")) {
          const body = JSON.parse(init!.body as string);
          calls.push({ url: u, method: init!.method!, body });
          const label = body.source_asset_id === "zip1" ? "shop.zip" : null;
          return json({ ...VERIFIED, source_asset_id: body.source_asset_id, source_label: label });
        }
        return json(VERIFIED);
      }),
    );
    const host = await mount({ assetId: "a1" });
    const select = host.querySelector("#wav-linked-source") as HTMLSelectElement;
    expect(select.value).toBe("src1");
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(["Not linked", "github.com/acme/shop", "shop.zip"]);
    const save = () => Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Save link")!;
    expect(save().disabled).toBe(true); // nothing changed yet

    for (const [value, said] of [["zip1", "Linked to shop.zip."], ["", "No longer linked."]] as const) {
      await act(async () => {
        select.value = value;
        select.dispatchEvent(new Event("change", { bubbles: true }));
      });
      await act(async () => save().click());
      await act(async () => {
        await new Promise((r) => setTimeout(r, 20));
      });
      expect(host.querySelector('[role="status"]')?.textContent).toBe(said);
    }
    expect(calls).toEqual([
      { url: expect.stringContaining("/assets/a1/source"), method: "PUT", body: { source_asset_id: "zip1" } },
      { url: expect.stringContaining("/assets/a1/source"), method: "PUT", body: { source_asset_id: null } },
    ]);
    expect(host.textContent).toContain("Verified"); // the link never touched verification
  });

  it("keeps a linked project choosable when the project list cannot load", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        String(url).includes("/assets?")
          ? json({ detail: "boom" }, 500)
          : json({ ...PENDING, source_asset_id: "src1", source_label: "github.com/acme/shop" }),
      ),
    );
    const host = await mount({ assetId: "a1" });
    const select = host.querySelector("#wav-linked-source") as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(["Not linked", "github.com/acme/shop"]);
    expect(select.value).toBe("src1");
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
