import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import { API_URL, E2E_TOKEN } from "../playwright.config";
import { projectName } from "../lib/format";
import { expectAccessible, newProject, signIn, uniqueRepoUrl } from "./helpers";

/**
 * Journeys J6-J10 (plan §53.1, Week 74), against the real app and the real API -- see
 * scripts/e2e_server.py for what that server stands in for (scanners, the parser sandbox, the
 * advisory feeds, GitHub's Issues API) and why. The plan's targets ("under 1 minute", ...) are a
 * person's pace, measured by the usability study (docs/ux-study.md); these assert each journey
 * completes on the real screens with no dead end.
 */

const GOLDEN = path.resolve(__dirname, "../../tests/golden/ingest");

test.describe("J6 — import a report from a tool you don't run", () => {
  test("upload a Nessus export, see the preview counts, confirm, and see the same numbers", async ({ page }) => {
    const project = await newProject(page, "payments-api");
    await page.goto(`/app/projects/${project.id}/import`);
    await expect(page.getByRole("heading", { name: "Import a report" })).toBeVisible();
    await expect(page.getByText(/Nessus \/ Tenable report/)).toBeVisible(); // the picker says it reads it

    await page.getByLabel("Report file").setInputFiles(path.join(GOLDEN, "defectdojo/nessus/nessus_many_vuln2-default.csv"));
    await expect(page.getByRole("heading", { name: "Import results" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(/looks like\s+Nessus \/ Tenable report/)).toBeVisible();
    const counts = page.getByRole("list", { name: "What would change" });
    await expect(counts).toContainText("29 new");
    await expect(counts).toContainText("0 closed");
    await expect(page.getByText("Nothing is saved until you import.")).toBeVisible();
    await expectAccessible(page, "the import preview");

    await page.getByRole("button", { name: "Import file" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Imported:" })).toHaveText("Imported: 29 new, 0 reopened, 0 closed", { timeout: 15_000 });

    await page.getByRole("link", { name: "View issues" }).click();
    await expect(page.getByRole("table")).toBeVisible();
    await expect(page.getByRole("table")).toContainText(/SSL|TLS/);
  });

  test("a second ZAP run that lists other pages holds the missing ones open, and says why", async ({ page }) => {
    // Two real, consecutive zap-baseline runs of one unchanged Juice Shop (tests/fixtures/dast).
    const fixtures = path.resolve(__dirname, "../../tests/fixtures/dast");
    const project = await newProject(page, "juice-shop");
    const auth = { Authorization: `Bearer ${E2E_TOKEN}` };
    const first = await page.request.post(`${API_URL}/v2/ingest`, {
      headers: auth,
      multipart: { project: project.id, file: { name: "zap-1.json", mimeType: "application/json",
        buffer: fs.readFileSync(path.join(fixtures, "zap-baseline-juiceshop-1.json")) } },
    });
    expect(first.status()).toBe(202);
    const firstId = (await first.json()).import_id;
    await expect.poll(async () => (await page.request.get(`${API_URL}/v2/imports/${firstId}`, { headers: auth }).then((r) => r.json())).status)
      .toBe("applied");

    await page.goto(`/app/projects/${project.id}/import`);
    await page.getByLabel("Report file").setInputFiles(path.join(fixtures, "zap-baseline-juiceshop-2.json"));
    await expect(page.getByRole("heading", { name: "Import results" })).toBeVisible({ timeout: 15_000 });
    const counts = page.getByRole("list", { name: "What would change" });
    await expect(counts).toContainText("0 closed"); // was 4: pages this run simply didn't list
    await expect(page.getByText(/4 more issues are not in this file but stay open/)).toBeVisible();
    await expectAccessible(page, "the import preview with held issues");
  });
});

test.describe("J7 — the new-CVE morning", () => {
  test("where do we use log4j-core?, its impact, then one grouped Issue and a ticket", async ({ page }) => {
    const project = await newProject(page, "billing-service");
    // The morning's starting state: the project's SBOM (imported) and its ticket settings.
    const sbom = {
      bomFormat: "CycloneDX", specVersion: "1.5", version: 1,
      components: [{ type: "library", group: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1",
                     purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }],
    };
    const upload = await page.request.post(`${API_URL}/v2/ingest`, {
      headers: { Authorization: `Bearer ${E2E_TOKEN}` },
      multipart: { project: project.id, file: { name: "sbom.cdx.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(sbom)) } },
    });
    expect(upload.status()).toBe(202);
    const auth = { Authorization: `Bearer ${E2E_TOKEN}` };
    const importId = (await upload.json()).import_id;
    await expect.poll(async () => (await page.request.get(`${API_URL}/v2/imports/${importId}`, { headers: auth }).then((r) => r.json())).status)
      .toBe("applied");
    await page.request.put(`${API_URL}/settings/integrations`, { headers: auth, data: { github_token: "e2e-fake-token-not-a-secret", github_issues_repo: "acme/security" } });
    await page.request.put(`${API_URL}/v2/projects/${project.id}/tickets`, { headers: auth, data: { provider: "github", target: "acme/security" } });

    // "Where do we use this?"
    await page.goto("/app/components");
    await page.getByLabel("Library").fill("log4j-core");
    await page.keyboard.press("Enter"); // at once: the suggestions must not be needed (Week 74 fix)
    const result = page.getByRole("region", { name: /log4j-core is in \d+ projects?/ });
    await expect(result).toBeVisible({ timeout: 10_000 });
    await expect(result.getByRole("link", { name: projectName(project.url) })).toBeVisible(); // owner/repo, not the clone URL
    await expectAccessible(page, "the component search result");

    // Its impact.
    await result.getByRole("link", { name: "CVE-2021-44228" }).first().click();
    await expect(page.getByRole("heading", { name: "CVE-2021-44228", level: 1 })).toBeVisible();
    // Most important uses first; ours may be under "Show all" when other runs' projects use it too.
    const showAll = page.getByRole("button", { name: "Show all" });
    if (await showAll.isVisible()) await showAll.click();
    const row = page.getByRole("row").filter({ has: page.getByRole("link", { name: projectName(project.url) }) });
    await expect(row).toContainText("2.14.1");
    await expect(row).toContainText("2.15.0"); // the fixed version
    await expectAccessible(page, "the advisory impact view");

    // One grouped Issue per project, and a ticket where the project has ticket settings.
    await page.getByRole("button", { name: /^(Create Issues in \d+ projects?, grouped under CVE-2021-44228|Bring the Issues up to date)$/ }).click();
    await expect(page.getByText(/\d+ tickets? filed or updated\./)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Tickets failed")).toHaveCount(0);
    const issueLink = row.getByRole("link", { name: "Open" });
    await expect(issueLink).toBeVisible();
    const issueId = (await issueLink.getAttribute("href"))!.split("/").pop()!;
    const ticket = await page.request.get(`${API_URL}/v2/issues/${issueId}/ticket`, { headers: auth }).then((r) => r.json());
    expect(JSON.stringify(ticket)).toContain("acme/security");
  });
});

test.describe("J9 — a pen test, start to report", () => {
  test("create an engagement, record five findings, close it and get the report", async ({ page }) => {
    test.setTimeout(120_000);
    const project = await newProject(page, "storefront");
    await page.goto(`/app/projects/${project.id}/engagements`);
    await page.getByRole("button", { name: "New engagement" }).click();
    await page.getByLabel("Name").fill("Q4 external pentest");
    await page.getByLabel("In scope: targets").fill("shop.acme.example");
    await page.getByLabel("Lead").fill("Priya N.");
    await page.getByRole("button", { name: "Create engagement" }).click();
    await expect(page.getByRole("heading", { name: "Q4 external pentest", level: 1 })).toBeVisible();
    const engagementUrl = page.url();
    await page.getByRole("button", { name: "Start testing" }).click();

    const findings = [
      ["IDOR on order history", "/v2/orders/{id}", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"],
      ["Stored XSS in product reviews", "/v2/reviews", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"],
      ["Password reset token never expires", "/v2/password-reset", "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"],
      ["Verbose stack traces on 500", "/v2/checkout", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"],
      ["No rate limit on login", "/v2/login", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"],
    ] as const;
    await page.getByRole("link", { name: "Add a finding" }).click();
    for (const [title, route, vector] of findings) {
      await expect(page.getByRole("heading", { name: "Record a finding" })).toBeVisible();
      if (title === findings[0][0]) await expectAccessible(page, "the manual finding form");
      await page.getByLabel("Title").fill(title);
      await page.getByLabel("Or paste a vector").fill(vector);
      await page.getByRole("button", { name: "Use vector" }).click();
      await expect(page.getByText(/CVSS 4\.0/).first()).toBeVisible();
      await page.getByLabel("Route path").fill(route);
      await page.getByLabel("Steps to reproduce").fill(`1. Sign in as a customer.\n2. Exercise ${route}.`);
      await page.getByLabel("Impact").fill("Customer data at risk.");
      await page.getByLabel("Recommendation").fill("Fix the check on the server.");
      await page.getByRole("button", { name: "Record finding" }).click();
      await expect(page.getByRole("status").filter({ hasText: `Recorded: ${title}` })).toBeVisible({ timeout: 10_000 });
      if (title !== findings.at(-1)![0]) await page.getByRole("button", { name: "Record another" }).click();
    }

    await page.getByRole("link", { name: "Back to the engagement" }).click();
    const listed = page.getByRole("region", { name: "Findings" });
    for (const [title] of findings) await expect(listed).toContainText(title);

    await page.getByRole("button", { name: "Move to reporting" }).click();
    await page.getByRole("button", { name: "Close and write the report" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("5 findings");
    await dialog.getByRole("textbox").fill("Five findings; the IDOR and the reset token need fixing first.");
    await dialog.getByRole("button", { name: "Close and write the report" }).click();
    await expect(page.getByText(/Closed\. The report is written/)).toBeVisible();
    await expectAccessible(page, "the closed engagement");

    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download Markdown" }).click();
    const file = await (await download).path();
    const report = (await import("node:fs")).readFileSync(file!, "utf8");
    for (const [title] of findings) expect(report).toContain(title);
    expect(report).toContain("Five findings; the IDOR and the reset token need fixing first.");
    expect(page.url()).toBe(engagementUrl);
  });
});

test.describe("J10 — the monthly report", () => {
  test("build it from a template, schedule it monthly, and see when it goes next", async ({ page }) => {
    await signIn(page);
    await page.goto("/app/reports");
    await page.getByLabel("Start from").selectOption({ label: "Weekly program summary" });
    await page.getByRole("button", { name: "Create" }).click();
    await expect(page.getByRole("heading", { name: "Weekly program summary", level: 1 })).toBeVisible();
    const name = `Monthly program summary ${crypto.randomUUID().slice(0, 6)}`;
    await page.getByLabel("Name").fill(name);
    await page.getByLabel("Covers the last").selectOption("30");
    // Every metric block is told apart by its metric (a Week 74 fix): no two identical buttons.
    const moves = await page.getByRole("button", { name: /^Move .* up$/ }).evaluateAll((els) => els.map((e) => e.getAttribute("aria-label")));
    expect(new Set(moves).size).toBe(moves.length);

    await page.getByRole("checkbox", { name: /on a schedule/ }).check();
    await page.getByLabel("How often").selectOption("Monthly");
    await page.getByLabel("Day of the month").fill("1");
    await page.getByLabel("Recipients, one email address per line").fill("security-lead@acme.example");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved." })).toBeVisible();
    await expectAccessible(page, "the report builder with a schedule");

    // Zero work after this: it says when it goes next, and that survives a reload.
    await page.reload();
    await expect(page.getByRole("heading", { name, level: 1 })).toBeVisible();
    await expect(page.getByText(/; next on /)).toBeVisible();
    await expect(page.getByLabel("How often")).toHaveValue("monthly");
    await expect(page.getByLabel("Recipients, one email address per line")).toHaveValue("security-lead@acme.example");
  });
});

test.describe("A web target's link to its code", () => {
  test("register a site linked to one project, relink it to another later, then unlink it", async ({ page }) => {
    const shop = await newProject(page, "shop");
    const adminUrl = uniqueRepoUrl("shop-admin"); // a second project, already signed in
    await page.goto("/app");
    await page.getByLabel("Repository URL").fill(adminUrl);
    await page.getByRole("button", { name: "Start scan" }).click();
    await expect(page.getByText("Unique findings")).toBeVisible({ timeout: 10_000 });
    const domain = `shop-${crypto.randomUUID().slice(0, 8)}.example.com`;

    await page.goto("/app/projects/new-web");
    await page.getByLabel("Domain").fill(domain);
    await page.getByLabel("Source code (optional)").selectOption({ label: shop.url });
    await page.getByRole("button", { name: "Register target" }).click();
    await expect(page.getByText("Not yet verified")).toBeVisible();
    const linked = page.getByLabel("Source code", { exact: true });
    await expect(linked).toHaveValue(shop.id);

    const assets: { id: string; label: string }[] = await (
      await page.request.get(`${API_URL}/assets`, { headers: { Authorization: `Bearer ${E2E_TOKEN}` } })
    ).json();
    const site = assets.find((a) => a.label === domain)!;
    const admin = { id: assets.find((a) => a.label === adminUrl)!.id, url: adminUrl };
    const before = await (
      await page.request.get(`${API_URL}/assets/${site.id}/verification`, { headers: { Authorization: `Bearer ${E2E_TOKEN}` } })
    ).json();

    // Later, on the site's own page: relink without registering again.
    await page.goto(`/app/projects/${site.id}/verify`);
    await expect(linked).toHaveValue(shop.id);
    await expect(page.getByRole("button", { name: "Save link" })).toBeDisabled();
    await linked.selectOption({ label: admin.url });
    await page.getByRole("button", { name: "Save link" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Linked to" })).toHaveText(`Linked to ${admin.url}.`);
    await expectAccessible(page, "a web target with its source link");

    await page.reload();
    await expect(linked).toHaveValue(admin.id);
    const after = await (
      await page.request.get(`${API_URL}/assets/${site.id}/verification`, { headers: { Authorization: `Bearer ${E2E_TOKEN}` } })
    ).json();
    expect(after.record_value).toBe(before.record_value); // the same token: verification untouched

    await linked.selectOption({ label: "Not linked" });
    await page.getByRole("button", { name: "Save link" }).click();
    await expect(page.getByRole("status").filter({ hasText: "linked" })).toHaveText("No longer linked.");
  });
});
