import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SOURCE, STORY } from "../lib/finding-story";
import { githubSlug, snippets } from "../lib/snippets";
import { whereItSits } from "../components/site/WhereItSits";
import demo from "../lib/demo-data.json";

const ROOT = join(__dirname, "..", "..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");
const byId = (id: string) => snippets("https://github.com/acme/bulwark").find((s) => s.id === id)!;

describe("the home page's 'Plug it in' snippets match what they show", () => {
  it("the CLI's flags and the build step exist", () => {
    const cli = read("cli/main.py");
    expect(cli).toMatch(/"--format", help="json \(default\), sarif, html or pdf\."/);
    expect(cli).toMatch(/typer\.Option\(\s*None,\s*"--output",\s*"-o"/);
    expect(read("README.md")).toContain("docker compose --profile scanners build");
    expect(read("pyproject.toml")).toMatch(/\[project\.scripts\]\nbulwark = /);
    expect(byId("cli").code).toContain("--format sarif -o results.sarif");
  });

  it("the Action uses the action's real inputs and permissions, from this deployment's repository", () => {
    const action = read("action.yml");
    const docs = read("docs/github-action.md");
    expect(action).toMatch(/^ {2}fail-on:/m);
    for (const line of ["security-events: write", "pull-requests: write", "fail-on: high"]) expect(docs).toContain(line);
    expect(byId("action").code).toContain("uses: acme/bulwark@main");
    // Not configured: a placeholder, never someone else's repository.
    expect(snippets(null).find((s) => s.id === "action")!.code).toContain("uses: your-org/bulwark@main");
  });

  it("the MCP config is the one docs/mcp.md documents", () => {
    // The block sits inside a numbered step, so it is indented; JSON does not mind.
    const block = /```json\n([^`]*"mcpServers"[^`]*?)\n\s*```/.exec(read("docs/mcp.md"))![1]!;
    expect(JSON.parse(byId("mcp").code)).toEqual(JSON.parse(block));
  });

  it("the API calls match the scan request schema and routes", () => {
    const schemas = read("api/schemas.py");
    expect(schemas).toMatch(/class GitSource\(BaseModel\):\n\s+type: Literal\["git"\]/);
    expect(schemas).toMatch(/class ScanRequest\(BaseModel\):\n\s+source: GitSource/);
    const main = read("api/main.py");
    expect(main).toMatch(/@app\.post\(\s*"\/scans",/);
    expect(main).toContain('"/scans/{scan_id}/findings"');
    const body = /-d '(\{.*\})'/.exec(byId("api").code)![1]!;
    expect(JSON.parse(body)).toEqual({ source: { type: "git", url: "https://github.com/OWASP/NodeGoat" } });
  });

  it("never points at localhost or the default API port (the public sample build shows them too)", () => {
    for (const s of snippets(null)) expect(s.code).not.toMatch(/localhost|:8000/);
  });

  it("reads owner/repo only from a GitHub repository URL", () => {
    expect(githubSlug("https://github.com/rago12bit/cybernatics")).toBe("rago12bit/cybernatics");
    expect(githubSlug("https://github.com/acme/bulwark.git")).toBe("acme/bulwark");
    for (const other of [null, "https://gitlab.com/acme/bulwark", "https://github.com/acme", "https://github.com/acme/b/tree/main"]) {
      expect(githubSlug(other)).toBeNull();
    }
  });
});

describe("'Follow one finding' is the real scan of the fixture", () => {
  it("shows the fixture's own lines", () => {
    const lines = read("tests/fixtures/vuln-py/src/users.py").split("\n");
    for (const [n, text] of SOURCE) expect(lines[n - 1]).toBe(text);
  });

  it("reads every value from the recorded scan", () => {
    const f = demo.findings.find((x) => x.fingerprint === STORY.fingerprint)!;
    expect(f.evidence.reported_by).toEqual(["bandit", "semgrep"]);
    expect(STORY.reports.map((r) => r.rule)).toEqual(["B608", "python.sqlalchemy.security.sqlalchemy-execute-raw-query"]);
    expect(STORY.reports.map((r) => r.severity)).toEqual(["MEDIUM", "ERROR"]);
    expect(STORY.cwe).toEqual(["CWE-89"]);
    expect(STORY.severity).toBe("HIGH");
    expect(STORY.riskScore).toBe(f.scoring.risk_score);
  });

  it("every file a step cites exists", () => {
    const src = readFileSync(join(__dirname, "..", "components", "site", "FindingStory.tsx"), "utf8");
    const cited = [...src.matchAll(/src: "([^"]+)"/g)].flatMap((m) => m[1]!.split("·").map((x) => x.trim()));
    expect(cited.length).toBeGreaterThan(10);
    expect(cited.filter((p) => !existsSync(join(ROOT, p.replace(/\/$/, ""))))).toEqual([]);
  });

  it("states the merge rule the engine applies", () => {
    expect(read("core/correlation/engine.py")).toMatch(/^LINE_WINDOW = 3\b/m); // "lines within 3"
    const matrix = read("docs/severity-matrix.md");
    expect(matrix).toMatch(/\| semgrep \| — \| ERROR \|/); // ERROR is the HIGH column
    expect(matrix).toMatch(/\| bandit \| — \| HIGH \| MEDIUM \|/); // MEDIUM stays MEDIUM
  });
});

describe("'Where it sits' lists only what the catalogue has", () => {
  it("names every picked integration, and counts from the catalogue", () => {
    const { inputs, outputs, decides } = whereItSits();
    const text = JSON.stringify({ inputs, outputs, decides });
    for (const name of ["SARIF", "Nessus", "Burp Suite", "ZAP", "Snyk", "Dependabot", "DefectDojo", "Jira", "GitHub Issues", "Slack", "Microsoft Teams"]) {
      expect(text).toContain(name);
    }
    expect(text).toContain("Reports in 14 formats");
    expect(decides[0]).toBe("13 scanners, each in its own sandbox");
  });
});
