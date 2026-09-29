import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { FindingDetail } from "../components/FindingDetail";
import type { Finding } from "../lib/types";

// A malicious repository controls: file paths, code snippets, rule text, titles and references.
// Threat T9: none of it may ever execute or become a dangerous link in the report UI.
const EVIL = `<img src=x onerror="alert(1)"><script>alert(2)</script>`;

const hostile: Finding = {
  id: "f", fingerprint: "fp",
  title: `Title ${EVIL}`,
  description: `Desc ${EVIL}`,
  location: { path: `src/${EVIL}.py`, start_line: 1, end_line: 1, snippet: `x = "${EVIL}"  # </code></pre><script>alert(3)</script>` },
  taxonomy: {
    category: "sast",
    cwe: [`CWE-79" onmouseover="alert(4)`, "CWE-89"],
    owasp_top_10_2021: ["javascript:alert(5)"],
    cve: [`CVE-2021-1234"><script>alert(6)</script>`],
    aliases: [],
  },
  scoring: { native_severity: { [`tool${EVIL}`]: `HIGH${EVIL}` }, normalized_severity: "HIGH", cvss_v3_1: null, risk_score: null, confidence: 0.5 },
  evidence: { reported_by: ["bandit"], agreement_count: 1, rule_ids: { bandit: [`B1${EVIL}`] } },
  remediation: {
    summary: `Fix ${EVIL}`,
    references: ["javascript:alert(7)", "data:text/html,<script>alert(8)</script>", "http://insecure.example", "https://ok.example/path"],
    generated_by: "static",
  },
  package: { name: `pkg${EVIL}`, version: "1", ecosystem: "npm" },
  taint_path: [],
};

describe("report UI cannot be used for stored XSS", () => {
  const html = renderToStaticMarkup(<FindingDetail finding={hostile} scan={null} onClose={() => {}} />);

  it("escapes every scanner-derived string: no live tags from attacker data", () => {
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<img/i);
    expect(html).not.toMatch(/<[a-z][^>]*\son\w+\s*=/i); // no REAL tag has an event handler
    expect(html).toContain("onerror=&quot;alert(1)&quot;"); // ...it survives only as escaped text
    expect(html).toContain("&lt;script&gt;alert(2)&lt;/script&gt;"); // shown as inert text
  });

  it("the snippet cannot break out of its <pre><code> block", () => {
    const inner = html.split('<pre class="snippet"')[1]?.split("</pre>")[0] ?? "";
    expect(inner).toContain("&lt;/code&gt;&lt;/pre&gt;");
    expect((inner.match(/<\/pre>/g) ?? []).length).toBe(0);
  });

  it("only safe https links are emitted; malformed ids and bad URLs become plain text", () => {
    const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
    expect(hrefs.sort()).toEqual(["https://cwe.mitre.org/data/definitions/89.html", "https://ok.example/path"].sort());
    expect(html).not.toMatch(/href="javascript:/i);
    expect(html).not.toContain('href="data:');
    expect(html).not.toContain('href="http://insecure');
    for (const m of html.matchAll(/<a [^>]*href="https:[^"]*"[^>]*>/g)) {
      expect(m[0]).toContain('rel="noopener noreferrer"');
      expect(m[0]).toContain('target="_blank"');
    }
  });
});
