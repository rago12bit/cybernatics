import type { BulwarkFinding } from "./types";

/** Untrusted text (from scanned files, rule metadata or a model) must not become markdown syntax. */
export function escapeMd(text: string): string {
  return text
    .replace(/[\\`*_{}[\]()#+!|<>~&$]/g, "\\$&")
    .replace(/^(\s*)([-=]{2,})/gm, "$1\\$2")
    .replace(/\r?\n/g, "  \n");
}

export function cweUrl(id: string): string | null {
  const m = /^CWE-(\d{1,6})$/.exec(id);
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
}

/** Hover text for one finding. Plain markdown only; the caller must leave it untrusted (no commands, no HTML). */
export function hoverMarkdown(f: BulwarkFinding): string {
  const parts: string[] = [];
  const risk = f.riskScore === null ? "" : ` · risk ${f.riskScore}/100`;
  parts.push(`**${escapeMd(f.title)}**\n\n${f.severity}${risk}${f.category ? ` · ${escapeMd(f.category)}` : ""}`);
  if (f.riskFactors.length) parts.push(`*Why it ranks here:* ${f.riskFactors.map(escapeMd).join("; ")}`);
  if (f.description && f.description !== f.title) parts.push(escapeMd(f.description));
  const ids = [
    ...f.cwe.map((c) => {
      const u = cweUrl(c);
      return u ? `[${escapeMd(c)}](${u})` : escapeMd(c);
    }),
    ...f.owasp.map(escapeMd),
  ];
  if (ids.length) parts.push(ids.join(" · "));
  if (f.reachable === false) parts.push("Not imported by application code.");
  if (f.remediationSummary) parts.push(`*Fix:* ${escapeMd(f.remediationSummary)}`);
  if (f.suggestedPatch) {
    const who = f.patchSource === "llm" ? "AI-suggested" : "Scanner-suggested";
    parts.push(`${who} fix available: use Quick Fix (Cmd/Ctrl + .). Review it before applying.`);
  }
  const links = f.references.flatMap((u, i) => {
    try {
      const safe = new URL(u).href.replace(/[()]/g, (c) => (c === "(" ? "%28" : "%29"));
      return [`[reference ${i + 1}](${safe})`];
    } catch {
      return [];
    }
  });
  if (links.length) parts.push(links.join(" · "));
  parts.push(`Reported by ${f.tools.length ? f.tools.map(escapeMd).join(", ") : "Bulwark"}`);
  return parts.join("\n\n");
}
