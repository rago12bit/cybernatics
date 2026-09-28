import { test, expect, type Page } from "@playwright/test";
import { API_URL, E2E_TOKEN } from "../playwright.config";

/**
 * Real end-to-end journeys against the real Next.js app and the real FastAPI backend (real HTTP,
 * real SQLite persistence, real triage/audit-log writes) -- see scripts/e2e_server.py's module
 * docstring for the one thing that's stubbed (actual scanner containers) and why.
 *
 * Plan §26.2's targets (J1 under 2 minutes, J3 100 issues in 30 minutes) describe a *person's*
 * pace, not something a scripted test can assert -- these tests assert the flow completes with no
 * unnecessary step and no dead end, which is the part a test can actually verify.
 */

async function signIn(page: Page) {
  await page.goto("/app");
  await page.getByLabel("API token").fill(E2E_TOKEN);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Scan a codebase" })).toBeVisible();
}

// The (real) issue-tracking logic (ADR-0012) correctly recognizes the same finding recurring
// across scans of the same repository and reuses its existing Issue, triage state included --
// exactly what it's for. A distinct fake repo path per test is what actually gives each test its
// own independent asset and a fresh, untouched issue queue, not a coincidence of test order.
let counter = 0;
const uniqueRepoUrl = () => `https://github.com/OWASP/NodeGoat-e2e-${Date.now()}-${counter++}`;

test.describe("J1 — first scan", () => {
  test("sign in, submit a scan, watch it go live, land on a verdict", async ({ page }) => {
    await signIn(page);

    await page.getByLabel("Repository URL").fill(uniqueRepoUrl());
    await page.getByRole("button", { name: "Start scan" }).click();

    // The live scan screen (plan §28.2): a real status transition, not a fabricated one --
    // scripts/e2e_server.py's fake worker genuinely marks the scan running, then completed, a
    // moment later, exactly as the real Celery worker would (just without real scanner output).
    await expect(page.getByText(/queued|running/i).first()).toBeVisible({ timeout: 5_000 });
    await expect(page.locator(".elapsed")).toBeVisible();

    // The verdict: real findings, real severity counts, not placeholder copy.
    await expect(page.getByText("Unique findings")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/SQL injection in the login handler/).first()).toBeVisible();
    await expect(page.locator(".elapsed")).toHaveCount(0); // gone once the scan is done
  });
});

test.describe("J3 — triage", () => {
  // Each test's own asset, found by its exact label (not a link click): with several tests each
  // creating a "NodeGoat-e2e-..." project, a text/role match on the projects list is ambiguous
  // about *which* one, and clicking through is a slower way to land on the same assertion anyway.
  async function scanAndReachIssues(page: Page): Promise<void> {
    const url = uniqueRepoUrl();
    await signIn(page);
    await page.getByLabel("Repository URL").fill(url);
    await page.getByRole("button", { name: "Start scan" }).click();
    await expect(page.getByText("Unique findings")).toBeVisible({ timeout: 10_000 });

    const assets: { id: string; label: string }[] = await page
      .request.get(`${API_URL}/assets`, { headers: { Authorization: `Bearer ${E2E_TOKEN}` } })
      .then((r) => r.json());
    const asset = assets.find((a) => a.label === url);
    if (!asset) throw new Error(`no asset found for ${url}`);

    await page.goto(`/app/projects/${asset.id}/issues`);
    await expect(page.getByRole("table")).toBeVisible();
  }

  test("filter by severity, mark an issue as not a risk with a reason, and see it leave the active queue", async ({ page }) => {
    await scanAndReachIssues(page);

    await page.getByRole("button", { name: /critical/i }).click();
    await expect(page.getByText("AWS access key committed in config.py")).toBeVisible();
    await expect(page.getByText("SQL injection in the login handler")).not.toBeVisible();
    await page.getByRole("button", { name: /critical/i }).click(); // clear the filter

    await page.getByRole("link", { name: "SQL injection in the login handler" }).click();
    await expect(page.getByRole("heading", { name: "SQL injection in the login handler" })).toBeVisible();

    await page.getByRole("button", { name: "Mark as not a risk" }).click();
    await page.getByLabel(/reason/i).fill("Behind an internal-only admin gate; not reachable externally.");
    await page.getByRole("button", { name: "Confirm" }).click();

    // Real audit-log-backed history (Week 34), not a fabricated confirmation banner. ".first()":
    // the same words appear twice on purpose, once in the status banner and once in the history
    // list below it.
    await expect(page.getByText("Marked as not a risk").first()).toBeVisible();

    await page.goBack();
    await expect(page.getByText("SQL injection in the login handler")).not.toBeVisible(); // left the active queue
  });

  test("j/k moves between issues on the issue detail page (plan §30.1)", async ({ page }) => {
    await scanAndReachIssues(page);
    // The default sort is risk (highest first): the AWS key (95) ranks above the SQL injection
    // (82), so that's the order j/k must actually walk, not insertion order.
    await page.getByRole("link", { name: "AWS access key committed in config.py" }).click();
    await expect(page.getByRole("heading", { name: "AWS access key committed in config.py" })).toBeVisible();

    await page.keyboard.press("j");
    await expect(page.getByRole("heading", { name: "SQL injection in the login handler" })).toBeVisible();

    await page.keyboard.press("k");
    await expect(page.getByRole("heading", { name: "AWS access key committed in config.py" })).toBeVisible();
  });

  test("accept risk requires an expiry, and it reopens on request", async ({ page }) => {
    await scanAndReachIssues(page);
    await page.getByRole("link", { name: "AWS access key committed in config.py" }).click();

    await page.getByRole("button", { name: "Accept risk until…" }).click();
    const confirm = page.getByRole("button", { name: "Confirm" });
    await expect(confirm).toBeDisabled(); // no expiry yet
    await page.getByLabel(/expires/i).fill("2027-01-01");
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(page.getByText(/risk accepted/i).first()).toBeVisible();

    await page.getByRole("button", { name: "Reopen" }).click();
    await expect(page.getByText("Reopened")).toBeVisible();
  });
});
