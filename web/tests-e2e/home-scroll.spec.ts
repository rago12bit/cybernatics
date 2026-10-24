import { test, expect } from "@playwright/test";

/* The home page scrolled the way a person scrolls it, with motion on (every other spec runs with reduced
   motion, which is why none of them saw this). Its sections used to pin and slide over one another; on a
   busy machine, and in Safari, they were drawn through each other mid-scroll. Sections now simply follow
   one another: no two may overlap at any point, and everything that fades in must arrive. */

test.use({ reducedMotion: "no-preference", viewport: { width: 1000, height: 556 } });

test("home page sections never overlap while scrolling, and nothing stays hidden", async ({ page }) => {
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  const height = await page.evaluate(() => document.documentElement.scrollHeight);
  const overlaps = new Set<string>();
  for (let y = 0; y < height; y += 250) {
    await page.mouse.wheel(0, 250);
    await page.waitForTimeout(60);
    for (const pair of await page.evaluate(() => {
      // Every block the page is made of, whatever wraps it (the old stack wrapped each section in a div).
      const secs = [...document.querySelectorAll(".page > *")]
        .filter((e) => e.getBoundingClientRect().height > 0 && getComputedStyle(e).position !== "fixed")
        .map((e) => ({ id: e.id || e.firstElementChild?.id || String(e.className), r: e.getBoundingClientRect() }));
      return secs.slice(1).flatMap((s, i) => (s.r.top < secs[i]!.r.bottom - 1 ? [`${secs[i]!.id} / ${s.id}`] : []));
    })) overlaps.add(pair);
  }
  expect([...overlaps]).toEqual([]);
  await page.waitForTimeout(1500);
  expect(await page.locator("[data-reveal=armed]").count()).toBe(0);
});
