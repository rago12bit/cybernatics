// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SignIn } from "../components/SignIn";
import { TokenGate } from "../components/TokenGate";
import { MyTokens } from "../components/identity/MyTokens";
import { PeopleScreen } from "../components/identity/PeopleScreen";
import { SignInSettings } from "../components/identity/SignInSettings";
import type { UserView } from "../lib/identity";

vi.mock("next/navigation", () => ({ usePathname: () => "/app/settings/people", useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const SESSION = { user: { id: "u1", email: "boss@acme.test", name: "Boss", role: "admin" }, csrf: "csrf-123", method: "oidc", expires_at: "2026-10-08T00:00:00Z" };

function person(over: Partial<UserView> = {}): UserView {
  return { id: "u2", email: "meera@acme.test", name: "Meera S", role: "member", active: true, source: "scim", external_id: "00u1",
    created_at: "2026-10-01T00:00:00Z", last_login_at: "2026-10-06T09:00:00Z", disabled_at: null, deprovisioned_at: null,
    github_login: null, actor: "user:u2", roles: [], ...over };
}

type Call = { method: string; path: string; body?: unknown; headers: Headers; credentials?: string };
function api(routes: Record<string, (body: unknown, method: string) => Response>) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname + u.search, body, headers: new Headers(init?.headers), credentials: init?.credentials });
    const key = `${method} ${u.pathname}`;
    const handler = routes[key] ?? routes[u.pathname];
    return handler ? handler(body, method) : json({}, 404);
  }));
  return calls;
}

let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });
async function mount(el: React.ReactElement) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(el));
  await flush(60);
  return host;
}
const button = (scope: ParentNode, text: string) =>
  Array.from(scope.querySelectorAll("button")).find((b) => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim().startsWith(text)) as HTMLButtonElement;
async function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event("input", { bubbles: true })));
}
const byLabel = (scope: ParentNode, text: string) => {
  const label = [...scope.querySelectorAll("label")].find((l) => l.textContent?.startsWith(text))!;
  return scope.querySelector(`#${CSS.escape(label.htmlFor)}`) as HTMLInputElement;
};

beforeEach(() => { sessionStorage.clear(); });
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("signing in", () => {
  it("finds the organization's provider from a work email and goes to it", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const calls = api({ "/auth/sso/discover": () => json({ providers: [{ id: "p1", name: "Acme SSO", kind: "oidc" }] }) });
    const host = await mount(<SignIn next="/app/issues" />);
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await type(byLabel(host, "Work email"), "priya@acme.test");
    await act(async () => button(host, "Continue").click());
    await flush();
    expect(calls[0]!.path).toBe("/auth/sso/discover?email=priya%40acme.test");
    expect(calls[0]!.headers.get("Authorization")).toBeNull();
    expect(assign).toHaveBeenCalledWith("http://localhost:8000/auth/sso/p1/start?next=%2Fapp%2Fissues");
  });

  it("says plainly when a domain has no single sign-on, and offers a token", async () => {
    api({ "/auth/sso/discover": () => json({ providers: [] }) });
    const host = await mount(<SignIn next="/app" />);
    await type(byLabel(host, "Work email"), "x@gmail.com");
    await act(async () => button(host, "Continue").click());
    await flush();
    expect(host.textContent).toContain("does not sign in with single sign-on here");
    expect(host.querySelector<HTMLDetailsElement>("details")!.open).toBe(true);
  });

  it("explains a sign-in that did not work, from the provider's redirect", async () => {
    api({});
    const host = await mount(<SignIn next="/app" error="no_account" />);
    expect(host.querySelector('[role="alert"]')!.textContent).toBe("You have no account here yet. Ask an admin to add you.");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
  });

  it("lets a signed-in browser through, and sends its CSRF token with changes", async () => {
    const calls = api({
      "/auth/session": () => json(SESSION),
      "GET /v2/users": () => json([person()]),
      "PATCH /v2/users/u2": (b) => json(person(b as Partial<UserView>)),
      "/assets": () => json([]),
      "/v2/portfolios": () => json([]),
    });
    const host = await mount(<TokenGate><PeopleScreen /></TokenGate>);
    await flush();
    expect(host.textContent).toContain("Meera S");
    const select = byLabel(host, "Organization role of Meera S") as unknown as HTMLSelectElement;
    select.value = "viewer";
    await act(async () => select.dispatchEvent(new Event("change", { bubbles: true })));
    await flush();
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect(patch.body).toEqual({ role: "viewer" });
    expect(patch.headers.get("X-Bulwark-CSRF")).toBe("csrf-123");
    expect(patch.credentials).toBe("include");
    expect(patch.headers.get("Authorization")).toBeNull();
    expect(host.textContent).toContain("Meera S is now Viewer.");
  });
});

describe("people and access", () => {
  it("turns someone off only after saying what that does", async () => {
    sessionStorage.setItem("bulwark.token", "t".repeat(24));
    const calls = api({
      "GET /v2/users": () => json([person(), person({ id: "u3", email: "gone@acme.test", name: "Gone", active: false, deprovisioned_at: "2026-10-05T00:00:00Z" })]),
      "PATCH /v2/users/u2": (b) => json(person(b as Partial<UserView>)),
      "/assets": () => json([{ id: "a1", label: "acme/payments-api" }]),
      "/v2/portfolios": () => json([{ id: "pf1", name: "Payments" }]),
      "PUT /v2/users/u2/roles": (b) => json(person({ roles: [{ id: "o1", ...(b as object) } as UserView["roles"][number]] })),
    });
    const host = await mount(<PeopleScreen />);
    expect(host.textContent).toContain("Removed by your identity provider");
    expect(host.textContent).toContain("from your identity provider");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Turn off Meera S").click());
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
    expect(dialog.textContent).toContain("signed out everywhere now, and every API token they made stops working");
    await act(async () => button(dialog, "Turn off").click());
    await flush();
    expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ active: false });
    // A higher role on one project.
    await act(async () => button(host, "Change higher roles of Meera S").click());
    const d2 = document.querySelector<HTMLElement>('[role="dialog"]')!;
    const target = byLabel(d2, "Project") as unknown as HTMLSelectElement;
    target.value = "a1";
    await act(async () => target.dispatchEvent(new Event("change", { bubbles: true })));
    await act(async () => button(d2, "Give this role").click());
    await flush();
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ target_type: "project", target_id: "a1", role: "member" });
    expect((await axe.run(d2, AXE)).violations).toEqual([]);
  });

  it("links a GitHub account for /fix, and unlinks it", async () => {
    sessionStorage.setItem("bulwark.token", "t".repeat(24));
    const calls = api({
      "GET /v2/users": () => json([person()]),
      "PATCH /v2/users/u2": (b) => json(person(b as Partial<UserView>)),
      "/assets": () => json([]),
      "/v2/portfolios": () => json([]),
    });
    const host = await mount(<PeopleScreen />);
    const input = byLabel(host, "GitHub username of Meera S");
    expect(input.value).toBe("");
    expect(button(host, "Save")).toBeUndefined(); // nothing to save yet
    await type(input, "@meera-s");
    await act(async () => button(host, "Save").click());
    await flush();
    expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ github_login: "meera-s" });
    expect(host.textContent).toContain("Meera S can now use /fix on pull requests as @meera-s.");
    expect(byLabel(host, "GitHub username of Meera S").value).toBe("meera-s");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await type(byLabel(host, "GitHub username of Meera S"), "");
    await act(async () => button(host, "Save").click());
    await flush();
    expect(calls.filter((c) => c.method === "PATCH")[1]!.body).toEqual({ github_login: null });
    expect(host.textContent).toContain("GitHub account is unlinked");
  });
});

describe("sign-in settings", () => {
  it("adds an OIDC provider and shows what to give the provider; makes a SCIM token once", async () => {
    sessionStorage.setItem("bulwark.token", "t".repeat(24));
    const provider = { id: "p1", kind: "oidc", name: "Acme SSO", enabled: true, email_domains: ["acme.test"], auto_create: false,
      default_role: "member", secret_store: "database", has_secret: true, updated_at: "", updated_by: "",
      oidc: { issuer: "https://idp.acme.test", client_id: "bulwark", trust_email: false, redirect_uri: "https://api.acme.test/auth/oidc/callback" } };
    let providers: unknown[] = [];
    const calls = api({
      "GET /v2/sso/providers": () => json(providers),
      "POST /v2/sso/providers": () => { providers = [provider]; return json(provider, 201); },
      "GET /v2/scim/tokens": () => json({ base_url: "https://api.acme.test/scim/v2", tokens: [] }),
      "POST /v2/scim/tokens": () => json({ id: "t1", name: "Okta", prefix: "bwk_", token: "bulwark_secret_once", base_url: "", created_at: "", expires_at: null, last_used_at: null, revoked_at: null }, 201),
    });
    const host = await mount(<SignInSettings />);
    expect(host.textContent).toContain("No identity provider yet");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Add an OIDC provider").click());
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
    await type(byLabel(dialog, "Name people see"), "Acme SSO");
    await type(byLabel(dialog, "Issuer"), "https://idp.acme.test");
    await type(byLabel(dialog, "Client ID"), "bulwark");
    await type(byLabel(dialog, "Client secret"), "s3cret");
    await type(byLabel(dialog, "Email domains"), "acme.test, acme.co.uk");
    expect((await axe.run(dialog, AXE)).violations).toEqual([]);
    await act(async () => button(dialog, "Save").click());
    await flush();
    expect(calls.find((c) => c.method === "POST" && c.path === "/v2/sso/providers")!.body).toMatchObject({
      kind: "oidc", name: "Acme SSO", issuer: "https://idp.acme.test", client_id: "bulwark", client_secret: "s3cret",
      email_domains: ["acme.test", "acme.co.uk"] });
    expect(byLabel(host, "Redirect URI").value).toBe("https://api.acme.test/auth/oidc/callback");
    expect(host.textContent).toContain("not encrypted");
    await type(byLabel(host, "New token for"), "Okta");
    await act(async () => button(host, "Make a SCIM token").click());
    await flush();
    expect(byLabel(host, "The token").value).toBe("bulwark_secret_once");
    await act(async () => button(host, "I have copied it").click());
    expect(host.textContent).not.toContain("bulwark_secret_once");
  });
});

describe("my API tokens", () => {
  it("makes a token with chosen scopes, shows it once, and revokes it", async () => {
    sessionStorage.setItem("bulwark.token", "t".repeat(24));
    let tokens: unknown[] = [];
    const calls = api({
      "GET /v2/me/tokens": () => json(tokens),
      "POST /v2/me/tokens": (b) => { tokens = [{ id: "k1", name: "CI", prefix: "bwk_ab", scopes: (b as { scopes: string[] }).scopes, created_at: "", expires_at: "2027-01-05T00:00:00Z", last_used_at: null, revoked_at: null }]; return json({ ...(tokens[0] as object), token: "bulwark_once" }, 201); },
      "DELETE /v2/me/tokens/k1": () => new Response(null, { status: 204 }),
    });
    const host = await mount(<MyTokens />);
    await type(byLabel(host, "Name"), "CI");
    const write = [...host.querySelectorAll<HTMLLabelElement>(".idn-check")].find((l) => l.textContent?.includes("scans:write"))!;
    await act(async () => write.querySelector("input")!.click());
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Make a token").click());
    await flush();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ name: "CI", scopes: ["scans:read", "scans:write"], days: 90 });
    expect(byLabel(host, "Your token").value).toBe("bulwark_once");
    await act(async () => button(host, "Revoke CI").click());
    await flush();
    expect(calls.some((c) => c.method === "DELETE")).toBe(true);
  });
});
