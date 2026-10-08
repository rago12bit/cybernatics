import path from "node:path";
import { test, expect, type Page } from "@playwright/test";
import { API_URL, E2E_TOKEN } from "../playwright.config";

/**
 * Visual regression snapshots (plan §31's quality gates). Only stable, terminal-state screens --
 * the live scan screen has a ticking elapsed-time clock, which would make every run a diff for a
 * reason nobody cares about.
 */

// Fixed, not Date.now()-based like journeys.spec.ts's isolation trick: the asset's label (this
// URL) is rendered on screen, so a screenshot needs the exact same bytes on every run to compare
// cleanly -- a real, once-flaky failure found by actually re-running the comparison after
// generating a baseline, not assumed. One literal per test is still enough to keep the three
// visual tests from colliding with each other if Playwright runs them in parallel against the
// same server process.
async function signedInScanAsset(page: Page, repoSuffix: string): Promise<string> {
  const url = `https://github.com/OWASP/NodeGoat-e2e-visual-${repoSuffix}`;
  await page.goto("/app");
  await page.getByText("Use an API token instead").click(); // single sign-on comes first
  await page.getByLabel("API token").fill(E2E_TOKEN);
  await page.getByRole("button", { name: "Use this token" }).click();
  await page.getByLabel("Repository URL").fill(url);
  await page.getByRole("button", { name: "Start scan" }).click();
  await expect(page.getByText("Unique findings")).toBeVisible({ timeout: 10_000 });

  const assets: { id: string; label: string }[] = await page
    .request.get(`${API_URL}/assets`, { headers: { Authorization: `Bearer ${E2E_TOKEN}` } })
    .then((r) => r.json());
  const asset = assets.find((a) => a.label === url);
  if (!asset) throw new Error(`no asset found for ${url}`);
  return asset.id;
}

test.describe("visual regression", () => {
  test("project overview", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "project-overview");
    await page.goto(`/app/projects/${assetId}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page).toHaveScreenshot("project-overview.png", { fullPage: true, mask: [page.locator("time")] });
  });

  test("issues table", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "issues-table");
    await page.goto(`/app/projects/${assetId}/issues`);
    await expect(page.getByRole("table")).toBeVisible();
    await expect(page).toHaveScreenshot("issues-table.png", { fullPage: true, mask: [page.locator("time")] });
  });

  test("issue detail", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "issue-detail");
    await page.goto(`/app/projects/${assetId}/issues`);
    await page.getByRole("link", { name: "SQL injection in the login handler" }).click();
    await expect(page.getByRole("heading", { name: "SQL injection in the login handler" })).toBeVisible();
    // The finding id in the topline embeds this scan's real, freshly-generated UUID (real identity,
    // not a fixture shortcut -- see scripts/e2e_server.py), so it's never the same twice.
    await expect(page).toHaveScreenshot("issue-detail.png", {
      fullPage: true,
      mask: [page.locator("time"), page.locator(".ds-issue-topline code")],
    });
  });
});

// --- Week 74: the screens journeys J6-J10 use (plan §58: "visual regression for every new screen").
// Fixed names and dates, and an advisory (lodash's CVE-2021-23337) no journey touches, so each
// picture is the same on every run of a fresh server.

const GOLDEN = path.resolve(__dirname, "../../tests/golden/ingest");
const auth = { Authorization: `Bearer ${E2E_TOKEN}` };

async function sbomInto(page: Page, projectId: string, name: string, version: string, purl: string) {
  const sbom = { bomFormat: "CycloneDX", specVersion: "1.5", version: 1,
                 components: [{ type: "library", name, version, purl: `${purl}@${version}` }] };
  const r = await page.request.post(`${API_URL}/v2/ingest`, {
    headers: auth,
    multipart: { project: projectId, file: { name: "sbom.cdx.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(sbom)) } },
  });
  const id = (await r.json()).import_id;
  await expect.poll(async () => (await page.request.get(`${API_URL}/v2/imports/${id}`, { headers: auth }).then((x) => x.json())).status).toBe("applied");
}

test.describe("visual regression, v3 screens", () => {
  test("import preview", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "import-preview");
    await page.goto(`/app/projects/${assetId}/import`);
    await page.getByLabel("Report file").setInputFiles(path.join(GOLDEN, "defectdojo/nessus/nessus_many_vuln2-default.csv"));
    await expect(page.getByRole("heading", { name: "Import results" })).toBeVisible({ timeout: 15_000 });
    await expect(page).toHaveScreenshot("import-preview.png", { fullPage: true, mask: [page.locator("time")] });
  });

  test("component search", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "components");
    await sbomInto(page, assetId, "left-pad", "1.3.0", "pkg:npm/left-pad"); // its own: no other test uses it
    await page.goto("/app/components?purl=pkg%3Anpm%2Fleft-pad");
    await expect(page.getByRole("region", { name: /left-pad is in 1 project/ })).toBeVisible();
    await expect(page).toHaveScreenshot("component-search.png", {
      fullPage: true,
      mask: [page.locator("time"), page.getByText(/answered in \d+ ms/), page.getByRole("cell", { name: /import, / })],
    });
  });

  test("advisory impact", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "advisory");
    await sbomInto(page, assetId, "lodash", "4.17.20", "pkg:npm/lodash");
    await page.goto("/app/advisories/CVE-2021-23337");
    await expect(page.getByRole("heading", { name: "CVE-2021-23337", level: 1 })).toBeVisible();
    await expect(page).toHaveScreenshot("advisory-impact.png", {
      fullPage: true,
      mask: [page.locator("time"), page.getByText(/first seen here/)],
    });
  });

  test("engagement", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "engagement");
    const e = await page.request.post(`${API_URL}/v2/projects/${assetId}/engagements`, {
      headers: auth,
      data: { name: "Q1 external pentest", engagement_type: "pentest", scope_targets: ["shop.acme.example"],
              scope_routes: ["/v2/"], out_of_scope: "Admin panel", lead: "Priya N.", testers: ["Arjun K."],
              starts_at: "2027-01-04T00:00:00Z", ends_at: "2027-01-29T00:00:00Z" },
    }).then((r) => r.json());
    await page.goto(`/app/engagements/${e.id}`);
    await expect(page.getByRole("heading", { name: "Q1 external pentest", level: 1 })).toBeVisible();
    await expect(page).toHaveScreenshot("engagement.png", { fullPage: true, mask: [page.locator("time")] });
  });

  test("manual finding form", async ({ page }) => {
    const assetId = await signedInScanAsset(page, "manual-finding");
    await page.goto(`/app/projects/${assetId}/findings/new`);
    await expect(page.getByRole("heading", { name: "Record a finding" })).toBeVisible();
    await expect(page).toHaveScreenshot("manual-finding.png", { fullPage: true, mask: [page.locator("time")] });
  });

  test("report builder", async ({ page }) => {
    await signedInScanAsset(page, "report-builder");
    await page.goto("/app/reports");
    await page.getByLabel("Start from").selectOption({ label: "Penetration test report" });
    await page.getByRole("button", { name: "Create" }).click();
    await expect(page.getByRole("heading", { name: "Penetration test report", level: 1 })).toBeVisible();
    await expect(page).toHaveScreenshot("report-builder.png", { fullPage: true, mask: [page.locator("time")] });
  });
});
