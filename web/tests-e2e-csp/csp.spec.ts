/* Every screen under the production Content-Security-Policy (proxy.ts), with no violations.
 *
 * `npm run e2e` drives `next dev`, whose policy allows inline styles and eval for Next's dev overlay,
 * so a page the production policy breaks still passes there. That is how Shiki's WebAssembly engine
 * shipped: in production the browser refused it and every code snippet on an Issue was plain text.
 * playwright.csp.config.ts serves `next build && next start` instead. */
import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import { API_URL, E2E_TOKEN } from "../playwright.config";
import { api, newProject } from "../tests-e2e/helpers";

const APP = path.join(__dirname, "..", "app");

/** Every page.tsx under app/, as a route pattern ("/app/projects/[id]/issues"). */
function routes(dir = APP): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return routes(full);
    return e.name === "page.tsx" ? ["/" + path.relative(APP, dir).split(path.sep).join("/")] : [];
  }).map((r) => (r === "/" ? r : r.replace(/\/$/, "")));
}

test("no page breaks the production CSP", async ({ page }) => {
  test.setTimeout(300_000);
  const violations: string[] = [];
  let current = "";
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      const el = e.target instanceof Element ? e.target.outerHTML.slice(0, 120) : "document";
      console.log(`CSP-VIOLATION ${e.violatedDirective} blocked=${e.blockedURI} at ${e.sourceFile}:${e.lineNumber} :: ${el}`);
    });
  });
  page.on("console", (m) => { if (m.text().startsWith("CSP-VIOLATION")) violations.push(`${current}: ${m.text()}`); });

  const first = await page.goto("/");
  const csp = first?.headers()["content-security-policy"] ?? "";
  expect(csp, "this must run against `next start`, not a reused `next dev` server").not.toContain("unsafe-inline");

  const { id } = await newProject(page);
  type Row = { issue?: { id: string }; location: { snippet?: string } };
  const { items }: { items: Row[] } = await api(page).get(`/assets/${id}/issues?limit=50`);
  const withCode = items.find((f) => f.issue && f.location.snippet && !f.location.snippet.startsWith("[snippet withheld"));
  const issueId = withCode!.issue!.id;
  const latest: { id: string } = (await api(page).get("/scans?limit=1"))[0]; // the scan newProject just ran
  // A threat model to draw. Generating one clones the real repository, which this API's fake scans
  // don't have (it answers 500), so without this the page only ever showed an error and the check
  // passed while the diagram was broken.
  const saved = await page.request.put(`${API_URL}/assets/${id}/threat-model`, {
    headers: { Authorization: `Bearer ${E2E_TOKEN}` },
    data: { mermaid: "flowchart LR\n  user([User]) --> web[Web app]\n  web --> db[(Database)]", stride: [] },
  });
  expect(saved.ok()).toBe(true);

  const ids: Record<string, string> = { "[id]": id, "[issueId]": issueId };
  const visits = routes()
    .map((r) => r.replace(/\[(id|issueId)\]/g, (k) => ids[k]!))
    .filter((r) => !r.includes("[")) // other entities' detail pages need their own seeding
    .concat(`/scans/${latest.id}`);
  // The page that showed the bug: an Issue with code, highlighted by Shiki.
  expect(visits).toContain(`/app/projects/${id}/issues/${issueId}`);

  for (const route of visits) {
    current = route;
    await page.goto(route);
    await page.waitForLoadState("networkidle");
  }
  expect(violations).toEqual([]);

  // And the Issue's code really is highlighted (it fell back to plain text when Shiki was refused).
  await page.goto(`/app/projects/${id}/issues/${issueId}`);
  await expect(page.locator(".ds-code-shiki .line").first()).toBeVisible({ timeout: 15_000 });

  // And the threat model's diagram is drawn with Mermaid's styles (unstyled, it was black boxes with
  // no visible arrows).
  await page.goto(`/app/projects/${id}/threat-model`);
  const drawing = page.frameLocator("iframe.ds-tm-frame").locator("svg");
  await expect(drawing.locator(".node")).toHaveCount(3, { timeout: 15_000 });
  const look = await drawing.evaluate((svg) => ({
    nodeFill: getComputedStyle(svg.querySelector(".node rect, .node path")!).fill,
    edgeStroke: getComputedStyle(svg.querySelector(".flowchart-link")!).stroke,
  }));
  expect(look.nodeFill).not.toBe("rgb(0, 0, 0)"); // what an unstyled shape falls back to
  expect(look.edgeStroke).not.toBe("none");
  const frameHeight = await page.locator("iframe.ds-tm-frame").evaluate((f) => f.getBoundingClientRect().height);
  expect(frameHeight).toBeGreaterThan(40);
  expect(violations).toEqual([]);
});
