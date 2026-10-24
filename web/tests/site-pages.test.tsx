// @vitest-environment jsdom
import axe from "axe-core";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import Community from "../app/community/page";
import Compare from "../app/compare/page";
import HowItWorks from "../app/how-it-works/page";
import Integrations from "../app/integrations/page";
import Migrate from "../app/migrate/page";
import Security from "../app/security/page";
import { metadata as notFoundMeta } from "../app/not-found";
import { IntegrationsCatalogue } from "../components/site/IntegrationsCatalogue";
import { Landing } from "../components/site/Landing";
import { Recording } from "../components/site/Recording";
import { SiteFooter } from "../components/site/SiteFooter";
import { SiteHeader } from "../components/site/SiteHeader";
import { LiveJuiceShopDemo } from "../components/LiveJuiceShopDemo";
import { INTEGRATIONS, counts, filterIntegrations, groupCount } from "../lib/catalogue";
import { codeFindings, codeScan, fingerprintCount, provenance, refusedTotal, runtimeFindings, runtimeScan, widthClass } from "../lib/recording";

vi.mock("next/navigation", () => ({ usePathname: () => "/", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const REPO = join(__dirname, "..", "..");
const PAGES = {
  "/how-it-works": HowItWorks,
  "/integrations": Integrations,
  "/security": Security,
  "/compare": Compare,
  "/migrate": Migrate,
  "/community": Community,
};
const html = (C: () => React.ReactNode) => renderToStaticMarkup(<C />);

afterEach(() => { document.body.innerHTML = ""; });

describe("the public site's pages (Week 77)", () => {
  it.each(Object.entries(PAGES))("%s emits no inline styles, scripts or handlers (the CSP would block them)", (_p, C) => {
    const out = html(C);
    expect(out).not.toMatch(/\sstyle=/i);
    expect(out).not.toMatch(/<script/i);
    expect(out).not.toMatch(/\son\w+\s*=/i);
  });

  it.each(Object.entries(PAGES))("%s passes an axe audit", async (_p, C) => {
    document.body.innerHTML = `<main>${html(C)}</main>`;
    const r = await axe.run(document.body, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`)).toEqual([]);
  });

  // A page that says "this lives in core/x.py" must be right: every repository path a page cites
  // (in a `src` line) has to exist, so a rename or a deletion fails here instead of misleading a reader.
  it("every file a page cites exists in the repository", () => {
    const files = [
      ...readdirSync(join(__dirname, "..", "app"), { recursive: true, encoding: "utf8" })
        .filter((f) => f.endsWith("page.tsx"))
        .map((f) => join(__dirname, "..", "app", f)),
      join(__dirname, "..", "components", "site", "Recording.tsx"),
    ];
    const cited = new Set<string>();
    for (const f of files) {
      const src = readFileSync(f, "utf8");
      for (const m of src.matchAll(/(?:src="([^"]+)"|className="src">([^<{]+)<)/g)) {
        for (const part of (m[1] ?? m[2] ?? "").split("·")) {
          const p = part.trim().split(" ")[0]!;
          if (/^(core|docs|tests|web|scripts|migrations|examples|\.github)\//.test(p) || /^[A-Z_]+\.md$/.test(p)) cited.add(p);
        }
      }
    }
    expect(cited.size).toBeGreaterThan(30);
    const missing = [...cited].filter((p) => !existsSync(join(REPO, p.replace(/\/$/, ""))));
    expect(missing).toEqual([]);
  });

  it("every site page is reachable from the footer, and all but the migration guides from the header", () => {
    const hrefs = (markup: string) => [...markup.matchAll(/href="([^"#]+)/g)].map((m) => m[1]);
    const footer = hrefs(renderToStaticMarkup(<SiteFooter />));
    const header = hrefs(renderToStaticMarkup(<SiteHeader />));
    for (const page of Object.keys(PAGES)) {
      expect(footer).toContain(page);
      if (page !== "/migrate") expect(header).toContain(page); // reached from Compare and the footer
    }
    expect(header).toContain("/sample");
  });

  it("the integrations page lists every integration the code knows, under its kind", () => {
    const out = renderToStaticMarkup(<IntegrationsCatalogue />);
    for (const i of INTEGRATIONS) expect(out).toContain(i.name.replace(/&/g, "&amp;"));
    const c = counts();
    expect(c.parsers).toBe(14); // core/imports/parsers/registry.py; update with the registry
    expect(c.scanners).toBeGreaterThanOrEqual(c.defaultScanners);
  });

  it("counts import formats the same on the integrations page as on the home page", () => {
    const c = counts();
    const out = renderToStaticMarkup(<IntegrationsCatalogue />);
    // The heading said "· 15" (it counted "any other report") while the home page said 14 formats.
    expect(out).toContain(`· ${c.parsers} formats + any other report`);
    expect(out).not.toContain(`· ${c.parsers + 1}<`);
    const imports = INTEGRATIONS.filter((i) => i.kind === "import");
    expect(groupCount("import", imports.filter((i) => i.id === "import:universal"))).toBe("any other report");
    expect(groupCount("import", imports.filter((i) => i.id === "import:sarif"))).toBe("1 format");
    expect(groupCount("connector", INTEGRATIONS.filter((i) => i.kind === "connector"))).toBe(String(c.connectors));
  });

  it("filters the catalogue by kind, category and words", () => {
    expect(filterIntegrations(INTEGRATIONS, "connector", "", "").every((i) => i.kind === "connector")).toBe(true);
    const dast = filterIntegrations(INTEGRATIONS, "all", "dast", "");
    expect(dast.map((i) => i.id)).toEqual(expect.arrayContaining(["scanner:zap-baseline", "import:zap", "import:burp"]));
    expect(dast.every((i) => (i.categories ?? []).includes("dast"))).toBe(true);
    expect(filterIntegrations(INTEGRATIONS, "all", "", "NESSUS").map((i) => i.id)).toEqual(["import:nessus"]);
    expect(filterIntegrations(INTEGRATIONS, "all", "", "no such thing")).toEqual([]);
    // What a visitor types is a category as often as a name (found by using the page).
    const typed = filterIntegrations(INTEGRATIONS, "all", "", "dast");
    expect(typed.map((i) => i.id).sort()).toEqual(dast.map((i) => i.id).sort());
    expect(filterIntegrations(INTEGRATIONS, "all", "", "dependencies").length).toBeGreaterThan(0);
  });

  it("the catalogue's filters work in a browser", async () => {
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    const root = createRoot(host);
    await act(async () => root.render(<IntegrationsCatalogue />));
    const search = host.querySelector<HTMLInputElement>('input[type="search"]')!;
    await act(async () => {
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
      set.call(search, "jira");
      search.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(host.querySelector('[role="status"]')!.textContent).toBe(`1 of ${INTEGRATIONS.length} integrations`);
    expect(host.textContent).toContain("Jira");
    await act(async () => root.unmount());
  });
});

describe("the 404 page", () => {
  it("has its own tab title, not the home page's", () => {
    expect(notFoundMeta.title).toBe("Page not found · Bulwark");
  });
});

describe("the recorded Juice Shop scan", () => {
  const out = renderToStaticMarkup(<Recording />);

  it("shows the recording's own numbers and where it came from", () => {
    expect(out).toContain(`${provenance.app} ${provenance.version}`);
    for (const n of [codeScan.raw_findings, codeScan.unique_findings, codeScan.raw_findings - codeScan.unique_findings, runtimeScan.raw_findings, refusedTotal()]) {
      expect(out).toContain(`>${n}<`);
    }
    expect(out).toContain(provenance.commit.slice(0, 12));
    expect(out).toContain(provenance.recorded_on);
  });

  it("labels each half's merged count, the one its severity bars add up to", () => {
    // The running app showed only its raw 47 alerts while its bars added up to the merged 38.
    for (const scan of [codeScan, runtimeScan]) {
      expect(out).toContain(`>${scan.unique_findings}</span><span class="label dimmed">After merging<`);
    }
  });

  it("says what it does not show", () => {
    for (const gap of ["Dependencies", "Nuclei", "five URLs", "Express", "withheld"]) expect(out).toContain(gap);
    expect(out).toContain(`the ${codeScan.unique_findings} code findings are ${fingerprintCount(codeFindings)} Issues`);
    expect(out).toContain(`the ${runtimeScan.unique_findings} running-app findings are ${fingerprintCount(runtimeFindings)}`);
    expect(out).not.toContain("kept nothing"); // Nuclei keeps what it found by its time limit now
  });

  it("is internally consistent", () => {
    const sev = (s: typeof codeScan) => Object.values(s.severity_counts).reduce((a, b) => a + (b ?? 0), 0);
    expect(sev(codeScan)).toBe(codeScan.unique_findings);
    expect(sev(runtimeScan)).toBe(runtimeScan.unique_findings);
    expect(runtimeFindings).toHaveLength(runtimeScan.unique_findings);
    expect(runtimeFindings.every((f) => f.location.path === "" && !!f.location.route)).toBe(true);
    // One finding per id: a repeat at the same place is folded into one finding (core.correlation).
    expect(new Set(codeFindings.map((f) => f.id)).size).toBe(codeFindings.length);
    expect(new Set(runtimeFindings.map((f) => f.id)).size).toBe(runtimeFindings.length);
    expect(provenance.image).toMatch(/@sha256:[0-9a-f]{64}$/);
  });

  it("is on the home page, right after the hero", () => {
    const home = renderToStaticMarkup(<Landing />);
    expect(home.indexOf('id="recording"')).toBeGreaterThan(home.indexOf('id="product"'));
    expect(home.indexOf('id="recording"')).toBeLessThan(home.indexOf('id="results"'));
  });

  it("bar widths stay in the stylesheet's 5% steps", () => {
    expect(widthClass(0, 10)).toBe("w-4");
    expect(widthClass(10, 10)).toBe("w-100");
    expect(widthClass(1, 100)).toBe("w-4");
    expect(widthClass(33, 100)).toBe("w-35");
  });
});

describe("/sample: both halves of the recording", () => {
  it("switches to the running app and shows where each alert was reached", async () => {
    vi.useFakeTimers();
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    const root = createRoot(host);
    await act(async () => root.render(<LiveJuiceShopDemo />));
    expect(host.textContent).toContain(provenance.version);
    const toRuntime = [...host.querySelectorAll("button")].find((b) => b.textContent?.startsWith("The running app"))!;
    expect(toRuntime.getAttribute("aria-pressed")).toBe("false");
    await act(async () => { toRuntime.click(); });
    await act(async () => { vi.advanceTimersByTime(500); });
    expect(toRuntime.getAttribute("aria-pressed")).toBe("true");
    const route = runtimeFindings[0]!.location.route!;
    expect(host.textContent).toContain(`${runtimeFindings[0]!.location.host}${route}`);
    expect(host.textContent).not.toMatch(/(^|\s):0(\s|$)/);
    await act(async () => root.unmount());
    vi.useRealTimers();
  });

  it("says raw output was withheld for secrets only where secrets were found", () => {
    const withheld = (s: typeof codeScan) => Object.values(s.tool_status).some((t) => t.raw_artifact === "withheld");
    expect(withheld(codeScan)).toBe(codeFindings.some((f) => f.taxonomy.category === "secrets"));
    expect(withheld(runtimeScan)).toBe(false);
  });

  it("emits no inline styles (the banner used one, which the CSP dropped)", () => {
    expect(renderToStaticMarkup(<LiveJuiceShopDemo />)).not.toMatch(/\sstyle=/i);
  });
});
