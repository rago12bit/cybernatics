// @vitest-environment jsdom
// The home page's "scan a GitHub repository": what it accepts, and signing in on the way to a scan.
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const goTo = vi.fn();
vi.mock("../lib/navigate", () => ({ goTo: (p: string) => goTo(p) }));

import { RepoScan } from "../components/site/RepoScan";
import { clearToken, setToken } from "../lib/api";
import { githubRepo } from "../lib/github";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe("what the repository box accepts", () => {
  it("turns owner/repo and any link inside a repository into the one URL the API takes", () => {
    for (const raw of ["OWASP/NodeGoat", " github.com/OWASP/NodeGoat ", "https://github.com/OWASP/NodeGoat.git",
      "https://www.github.com/OWASP/NodeGoat/tree/master/app", "http://github.com/OWASP/NodeGoat/"]) {
      expect(githubRepo(raw)).toEqual({ url: "https://github.com/OWASP/NodeGoat", slug: "OWASP/NodeGoat" });
    }
    expect(githubRepo("")).toBeNull();
  });

  it("says why it cannot scan something, instead of sending it to the API", () => {
    expect(githubRepo("gitlab.com/foo/bar")).toEqual({ error: expect.stringMatching(/only github/i) });
    expect(githubRepo("OWASP")).toEqual({ error: expect.stringMatching(/add the repository/i) });
    expect(githubRepo("-bad/repo")).toEqual({ error: expect.stringMatching(/user or organization/i) });
    expect(githubRepo("owner/..")).toEqual({ error: expect.stringMatching(/repository name/i) });
    expect(githubRepo("https://user:pw@github.com/a/b")).toEqual({ error: expect.anything() });
    expect(githubRepo("github.com/a/b?x=1")).toEqual({ error: expect.anything() });
  });
});

let host: HTMLDivElement;
let root: Root;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const input = () => host.querySelector<HTMLInputElement>("#scan-repo input")!;
const button = () => host.querySelector<HTMLButtonElement>("#scan-repo button")!;
async function type(value: string) {
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  await act(async () => { set.call(input(), value); input().dispatchEvent(new Event("input", { bubbles: true })); });
}
async function mount() {
  await act(async () => root.render(<RepoScan />));
  await act(async () => {}); // the session check settles
}

beforeEach(() => {
  goTo.mockReset();
  sessionStorage.clear();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  clearToken();
  vi.unstubAllGlobals();
});

describe("scanning a repository from the home page", () => {
  it("signed out: keeps the repository, sends you to sign in, and brings you back to it", async () => {
    const fetch = vi.fn(async (_u: string, _init?: RequestInit) => json(null, 401));
    vi.stubGlobal("fetch", fetch);
    await mount();
    expect(button().disabled).toBe(true); // nothing typed yet
    await type("https://github.com/OWASP/NodeGoat/tree/master");
    expect(host.textContent).toContain("Will scan https://github.com/OWASP/NodeGoat");
    expect(button().textContent).toMatch(/sign in and scan/i);
    await act(async () => button().click());
    expect(goTo).toHaveBeenCalledWith("/signin?next=%2F%23scan-repo");
    expect(fetch.mock.calls.some(([u]) => String(u).endsWith("/scans"))).toBe(false); // no scan without a sign-in

    // Back from signing in: the box has the repository again, once.
    await act(async () => root.unmount());
    root = createRoot(host);
    await mount();
    expect(input().value).toBe("OWASP/NodeGoat");
    expect(sessionStorage.getItem("bulwark.pendingRepo")).toBeNull();
  });

  it("signed in: starts the scan with the default scanners and opens it", async () => {
    setToken("t".repeat(24));
    const fetch = vi.fn(async (_u: string, _init?: RequestInit) => json({ id: "scan-1", status: "queued" }, 201));
    vi.stubGlobal("fetch", fetch);
    await mount();
    expect(host.textContent).toMatch(/signed in with an api token/i);
    await type("OWASP/NodeGoat");
    expect(button().textContent).toMatch(/scan this repository/i);
    await act(async () => button().click());
    const [url, init] = fetch.mock.calls.find(([u]) => String(u).endsWith("/scans"))!;
    expect(String(url)).toMatch(/\/scans$/);
    expect(JSON.parse(String(init!.body))).toEqual({
      source: { type: "git", url: "https://github.com/OWASP/NodeGoat" },
      tools: ["bandit", "semgrep", "gitleaks", "trivy", "osv-scanner"],
    });
    expect(goTo).toHaveBeenCalledWith("/scans/scan-1");
  });

  it("shows the API's refusal instead of moving on", async () => {
    setToken("t".repeat(24));
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "host 'github.com' did not resolve" }, 400)));
    await mount();
    await type("OWASP/NodeGoat");
    await act(async () => button().click());
    expect(host.querySelector("[role=alert]")?.textContent).toMatch(/did not resolve/);
    expect(goTo).not.toHaveBeenCalled();
    expect(button().disabled).toBe(false); // can try again
  });
});
