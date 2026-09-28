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
  await page.getByLabel("API token").fill(E2E_TOKEN);
  await page.getByRole("button", { name: "Continue" }).click();
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
