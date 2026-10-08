import { expect, type Page } from "@playwright/test";
import { API_URL, E2E_TOKEN } from "../playwright.config";

/** The token way in (single sign-on needs an identity provider; tests/integration has those). */
export async function useToken(page: Page, token: string) {
  await page.getByText("Use an API token instead").click();
  await page.getByLabel("API token").fill(token);
  await page.getByRole("button", { name: "Use this token" }).click();
}

export async function signIn(page: Page) {
  await page.goto("/app");
  await useToken(page, E2E_TOKEN);
  await expect(page.getByRole("heading", { name: "Scan a codebase" })).toBeVisible();
}

// Random, not a counter: each Playwright worker is its own process with its own counter.
export const uniqueRepoUrl = (name = "NodeGoat") =>
  `https://github.com/OWASP/${name}-e2e-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;

export const api = (page: Page) => ({
  get: (path: string) =>
    page.request.get(`${API_URL}${path}`, { headers: { Authorization: `Bearer ${E2E_TOKEN}` } }).then((r) => r.json()),
  post: (path: string, data?: unknown) =>
    page.request
      .post(`${API_URL}${path}`, { headers: { Authorization: `Bearer ${E2E_TOKEN}` }, data })
      .then((r) => r.json()),
});

/** A project of its own: scan a fresh repository URL through the UI and return the project id. */
export async function newProject(page: Page, name?: string): Promise<{ id: string; url: string }> {
  const url = uniqueRepoUrl(name);
  await signIn(page);
  await page.getByLabel("Repository URL").fill(url);
  await page.getByRole("button", { name: "Start scan" }).click();
  await expect(page.getByText("Unique findings")).toBeVisible({ timeout: 10_000 });
  const assets: { id: string; label: string }[] = await api(page).get("/assets");
  const asset = assets.find((a) => a.label === url);
  if (!asset) throw new Error(`no asset found for ${url}`);
  return { id: asset.id, url };
}


/** axe-core in the real browser (plan §58: "axe-core in CI"), WCAG 2.2 A and AA -- including colour
 * contrast, which the unit tests' jsdom cannot measure. */
export async function expectAccessible(page: Page, what: string) {
  await page.addScriptTag({ path: require.resolve("axe-core") });
  const violations = await page.evaluate(async () => {
    const w = window as unknown as { axe: { run: (ctx: unknown, opts: unknown) => Promise<{ violations: { id: string; help: string; nodes: { target: string[] }[] }[] }> } };
    const r = await w.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } });
    return r.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(" ")).slice(0, 3).join(", ")})`);
  });
  expect(violations, `accessibility violations on ${what}`).toEqual([]);
}
