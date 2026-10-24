import { test, expect } from "@playwright/test";

/**
 * No public page may scroll sideways on a phone. A UI audit found two that did: long file paths in
 * the recorded scan's "Fix these first" list, and the setup commands on /self-host, which widened
 * the whole page instead of scrolling inside their own box.
 */
const PAGES = ["/", "/how-it-works", "/integrations", "/security", "/compare", "/community", "/sample", "/migrate", "/self-host", "/signin"];

test.use({ viewport: { width: 375, height: 812 } });

for (const path of PAGES) {
  test(`${path} fits a 375px phone`, async ({ page }) => {
    await page.goto(path);
    await expect(page.locator("h1")).toBeVisible();
    await page.waitForLoadState("networkidle");
    if (path === "/sample") await expect(page.getByRole("heading", { name: /^Top \d+ by risk$/ })).toBeVisible();
    const { scroll, client } = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      client: document.documentElement.clientWidth,
    }));
    expect(scroll).toBeLessThanOrEqual(client);
  });
}
