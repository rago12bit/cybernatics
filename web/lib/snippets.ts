import { REPO_URL } from "./site";

// The home page's "Plug it in" snippets. Each is copied from the behaviour it shows, not written for
// the page: the CLI from `bulwark scan --help` and README.md, the Action from docs/github-action.md,
// the MCP client config from docs/mcp.md, the API calls from api/schemas.py's ScanRequest.
// tests/plug-in.test.ts checks them against those sources.

export type Snippet = { id: string; label: string; lang: string; file: string; when: string; code: string };

/** `owner/repo` of a GitHub repository URL, or null for anything else. */
export function githubSlug(url: string | null): string | null {
  const m = url ? /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?\/?$/.exec(url) : null;
  return m ? `${m[1]}/${m[2]}` : null;
}

export function snippets(repoUrl: string | null = REPO_URL): Snippet[] {
  // The Action is used from wherever this deployment's repository is published; never a hard-coded one.
  const action = githubSlug(repoUrl) ?? "your-org/bulwark";
  return [
    {
      id: "cli",
      label: "CLI",
      lang: "bash",
      file: "terminal",
      when: "On your machine or any CI runner. Needs Docker: every scanner runs in its own locked-down container.",
      code: [
        "# from a checkout of Bulwark: the CLI, then the scanner images it runs",
        "pip install -e .",
        "docker compose --profile scanners build",
        "",
        "bulwark scan https://github.com/OWASP/NodeGoat     # or a folder, or a .zip",
        "bulwark scan . --format sarif -o results.sarif      # also html and pdf",
      ].join("\n"),
    },
    {
      id: "action",
      label: "GitHub Action",
      lang: "yaml",
      file: ".github/workflows/bulwark.yml",
      when: "On every pull request: SARIF to Code Scanning, a comment with only what the change introduces, and a failing check at the severity you pick.",
      code: [
        "name: Bulwark",
        "on:",
        "  push:",
        "    branches: [main]",
        "  pull_request:",
        "permissions:",
        "  contents: read",
        "  security-events: write   # upload SARIF to Code Scanning",
        "  pull-requests: write     # the PR comment",
        "jobs:",
        "  scan:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        `      - uses: ${action}@main   # pin a release tag or commit SHA`,
        "        with:",
        "          fail-on: high         # on a PR, only new findings count",
      ].join("\n"),
    },
    {
      id: "mcp",
      label: "MCP",
      lang: "json",
      file: "your MCP client's config",
      when: "From your own agent: it can list and read Issues, verified fixes and where a library is used, as you and never more. It cannot triage or close anything.",
      code: [
        "{",
        '  "mcpServers": {',
        '    "bulwark": {',
        '      "command": "bulwark",',
        '      "args": ["mcp"],',
        '      "env": {',
        '        "BULWARK_API_URL": "https://bulwark.example.com",',
        '        "BULWARK_MCP_TOKEN": "bulwark_..."',
        "      }",
        "    }",
        "  }",
        "}",
      ].join("\n"),
    },
    {
      id: "api",
      label: "REST API",
      lang: "bash",
      file: "terminal",
      when: "From anything else: start a scan, then read its findings. A WebSocket streams each scanner as it finishes.",
      code: [
        'curl -X POST "$BULWARK_URL/scans" \\',
        '  -H "Authorization: Bearer $BULWARK_TOKEN" \\',
        '  -H "Content-Type: application/json" \\',
        `  -d '{"source": {"type": "git", "url": "https://github.com/OWASP/NodeGoat"}}'`,
        '# {"id": "…", "status": "queued"}',
        "",
        'curl "$BULWARK_URL/scans/$SCAN_ID/findings" \\',
        '  -H "Authorization: Bearer $BULWARK_TOKEN"',
      ].join("\n"),
    },
  ];
}
